import sys
import shlex, subprocess
import os.path
import logging as log
import argparse
from pythonjsonlogger import jsonlogger


def parse_args():
    parser = argparse.ArgumentParser(
        description='Modify APK(s) to allow certificates issued by users (other than system certificates)')
    parser.add_argument('--apps', '-a',
                        help='Comma-separated list of apps names (they need to be located in this folder)')
    parser.add_argument('--apps-file', '-f', help='Path to a file containing apps names, one per line.')
    parser.add_argument('--config-file', '-c', help='Path to the config file (default config/cpi.conf)')
    return parser.parse_args()


def decompile(apk):
    try:
        ret = subprocess.call(shlex.split("apktool empty-framework-dir"))
        logger.info('Decompiling {} ...'.format(apk))
        ret = subprocess.call(shlex.split("apktool d {} -o {}.d".format(apk, apk)))
    except Exception as e:
        logger.error('Error while decompiling {}:Exit code = {}:{}'.format(apk, ret, str(e)))
    else:
        if not ret:
            logger.info('Succesful decompilation of {}'.format(apk))


def compile(apk):
    try:
        ret = subprocess.call(shlex.split("apktool empty-framework-dir"))
        logger.info('Compiling {} ...'.format(apk))
        ret = subprocess.call(shlex.split("apktool b {}.d -o mod-{}".format(apk, apk)))
    except Exception as e:
        logger.error('Error while compiling {}:Exit code={}:{}'.format(apk, ret, str(e)))
    else:
        if not ret:
            logger.info('Succesful compilation of {}'.format(apk))


def sign(apk, keystore, alias, key):
    try:
        ret = subprocess.call(shlex.split(
            'jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore {} -storepass {} {} {}'.format(keystore,
                                                                                                             key, apk,
                                                                                                             alias)))
    except Exception as e:
        log.error('Error while signing {}:Exit code = {}:{}'.format(apk, ret, str(e)))
    else:
        if not ret:
            logger.info('Succesful signing of {}'.format(apk))


def set_new_certificates_source(apk):
    try:
        ret = -1
        manifest = open("{}.d/AndroidManifest.xml".format(apk), 'r')
        modified = open('AndroidManifest.xml', 'w')
        for line in manifest:
            if "<application" in line:
                if not "networkSecurityConfig" in line:
                    logger.info('Modifying {} AndroidManifest.xml to set new sources of certificates'.format(apk))
                    modified.write(
                        line.split(">")[0] + ' android:networkSecurityConfig="@xml/network_security_config"> ')
                else:
                    modified.write(line)
            else:
                modified.write(line)
        manifest.close()
        modified.close()
        ret = subprocess.call(shlex.split("cp AndroidManifest.xml {}.d/AndroidManifest.xml".format(apk)))
        ret = subprocess.call(shlex.split("rm AndroidManifest.xml"))
        if not os.path.isdir("{}.d/res/xml".format(apk)):
            logger.info('Folder xml not found in {}, creating it...'.format(apk))
            ret = subprocess.call(shlex.split("mkdir {}.d/res/xml".format(apk)))
        ret = subprocess.call(shlex.split("cp config/network_security_config.xml {}.d/res/xml".format(apk)))
    except Exception as e:
        logger.error('Error while setting new certificate source {}:Exit code={}:{}'.format(apk, ret, str(e)))
    else:
        if not ret:
            logger.info('Succesful setting of new certificate source {}'.format(apk))


# ..............................................................................
#                                             UTILS
# ..............................................................................
def parse_config_file(file):
    f = open(file, 'r')
    fields = f.readline().rstrip('\n').split(';')
    f.close()
    return fields


def read_apps_file(apps_file=None):
    if apps_file is not None:
        return [app.strip() for app in open(apps_file).readlines()]
    return []


def parse_apps_list(apps_list=None):
    if (apps_list is not None):
        return [app.strip() for app in apps_list.split(',')]
    return []


def init_logger(file):
    handler = log.FileHandler(file)
    format_str = '%(levelname)s%(asctime)s%(filename)s%(funcName)s%(lineno)d%(message)'
    formatter = jsonlogger.JsonFormatter(format_str)
    handler.setFormatter(formatter)
    logger = log.getLogger()
    logger.addHandler(handler)
    logger.setLevel(log.INFO)
    return logger


# ..............................................................................
#                                             MAIN
# ..............................................................................


if __name__ == "__main__":
    # Config logging
    logger = init_logger('/var/log/modify.privapp.log')
    # Get inputs
    args = parse_args()
    if args.config_file is None:
        config_file = 'config/cpi.conf'
    config_params = parse_config_file(config_file)
    apps = set(parse_apps_list(args.apps) + read_apps_file(args.apps_file))
    for apk in apps:
        decompile(apk)
        set_new_certificates_source(apk)
        compile(apk)
        sign('mod-' + apk, config_params[0], config_params[1], config_params[2])
