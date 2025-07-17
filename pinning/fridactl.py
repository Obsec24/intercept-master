#!/usr/bin/env python3
import frida
import sys
import os
import subprocess as sub
import json
from datetime import datetime
import importlib
import time
import threading

ip = sys.argv[1]
app = sys.argv[2]
testing_label = sys.argv[3]
version = sys.argv[4]

LOG_FILE = '/app/logging/log/operation.privapp.log'
FILENAME_PINNING_CASES = '/app/intercept-master/pinning/pinning_cases.js'
HELPER_JSON_LOGGER = '/app/logging-master/agent/helper/log.py'

# configure json logger
log = importlib.util.spec_from_file_location("log", HELPER_JSON_LOGGER)
log_module = importlib.util.module_from_spec(log)
log.loader.exec_module(log_module)
logger = log_module.init_logger(LOG_FILE) 

#assert os.path.isfile(HELPER_JSON_LOGGER), '%s  is not a valid file or path to file' % HELPER_JSON_LOGGER
#log = imp.load_source('log', HELPER_JSON_LOGGER)
#logger = log.init_logger(LOG_FILE)

# import adb and appt tools
#TOOLS_FILE = '/app/scripts/tools.py'
#assert os.path.isfile(TOOLS_FILE), '%s  is not a valid file or path to file' % TOOLS_FILE
#tools = imp.load_source('tools', TOOLS_FILE)

TOOLS_FILE = '/app/scripts/tools.py'
assert os.path.isfile(TOOLS_FILE), '%s is not a valid file or path to file' % TOOLS_FILE

spec = importlib.util.spec_from_file_location("tools", TOOLS_FILE)
tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tools)



# init adb tools
TOOLS_CONFIG = '/app/scripts/testing.config'
assert os.path.isfile(TOOLS_CONFIG), '%s  is not a valid file or path to file' % TOOLS_CONFIG
assert ip is not None, 'serial_device or IP device not provided'
tools.init(TOOLS_CONFIG, ip)

# store messages sent by instrumented app
PINNING_LOG = '/app/logging/log/frida.privapp.log'


def message_callback(message, data):
    if 'payload' in message:
        msg = json.loads(message['payload'])
        msg['testing_label'] = testing_label
        msg['apk'] = app
        msg['version'] = version
        msg['device'] = ip
        msg['asctime'] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        msg['levelname'] = "INFO"
        print(msg)
        log_data(msg, PINNING_LOG)
    else:
        msg = message
        msg['testing_label'] = testing_label
        msg['apk'] = app
        msg['version'] = version
        msg['device'] = ip
        msg['asctime'] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        msg['levelname'] = "ERROR"
        print(msg)
        log_data(msg, PINNING_LOG)


def log_data(entry, file):
    with open(file, "a") as f:
        json.dump(entry, f)
        f.write('\n')


# check whether the terminal is available
def get_device(ip):
    device = None
    (success, result) = tools.adb_call('devices')
    if not success:
        logger.error("No devices connected, stopping fridactl", extra={'testing_label': testing_label, 'apk': app,
                                                                       'version': version, 'container': 'traffic'})
        sys.exit(1)
    devices = frida.get_device_manager().enumerate_devices()
    if devices and len(devices) > 0:
        for d in devices:
            if d.id == ip:
                device = d
                break
    return device


# Send to the app the code to instrument
def attach_script(ip, app, file):
    device = get_device(ip)
    if device is None:
        logger.error("Device {} not connected".format(ip), extra={'testing_label': testing_label, 'apk': app,
                                                                  'version': version, 'container': 'traffic',
                                                                  'device': ip})
        sys.exit(1)
    if not tools.adb_package_installed(app):
        logger.error("App not installed, stopping fridactl", extra={'testing_label': testing_label, 'apk': app,
                                                                    'version': version, 'container': 'traffic','device': ip})
        sys.exit(1)
    (success, output) = tools.adb_start_app(app)  # execute the target app
    if not success:
        logger.error("Fail when fridactl tried to launch app, stopping fridactl",
                     extra={'testing_label': testing_label, 'apk': app,
                            'version': version, 'container': 'traffic', 'device': ip})
        sys.exit(1)
    pid = device.get_process(app).pid  # Get the id process of the app to hook
    if pid < 0:
        logger.error("Fail when fridactl tried to get PID, stopping fridactl",
                     extra={'testing_label': testing_label, 'apk': app,
                            'version': version, 'container': 'traffic', 'device': ip})
        sys.exit(1)
    process = device.attach(pid)  # Attach frida to the app process
    pinning_cases = None
    if not os.path.isfile(file):
        logger.error("Missing pinning cases file", extra={'testing_label': testing_label, 'apk': app,
                                                          'version': version, 'container': 'traffic', 'device': ip})
        sys.exit(1)
    with open(file) as f:
        pinning_cases = f.read()  # Read the bypassing pinning cases
    script = process.create_script(pinning_cases)  # Create a script object from our javascript pinning cases
    script.on('message',
              message_callback)  # Create a JS event listener to get callbacks from the JS pinning cases to the python frida wrapper
    script.load()  # Load the script into frida
    logger.debug("Pinning cases sent successfully", extra={'testing_label': testing_label, 'apk': app,
                                                          'version': version, 'container': 'traffic', 'device': ip})


# IMPORTANT  -> As fridactl.py is launched through nohup (avoiding it killed when shell is closed) sys.stdin.read() MUST NOT be used
condition = threading.Event()
thread = threading.Thread(target=attach_script, args=[ip, app, FILENAME_PINNING_CASES])
thread.start()
condition.wait()  # It never will be set() as we want to run it indefinidamente
