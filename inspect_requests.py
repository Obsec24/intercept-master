#!/usr/bin/python3

import pickle
import subprocess as sub

from mitmproxy import ctx
from mitmproxy.proxy.protocol import TlsLayer
from mitmproxy.exceptions import TlsProtocolException

import imp

dataf = "output.log"
datap = "pinning.log"
command = ""
LOG_FILE = "/app/logging/log/operation.privapp.log"

log = imp.load_source('log', '/app/logging/agent/helper/log.py')
logger =  log.init_logger(LOG_FILE)

# TLS layer wrapper to detect failed connections.
class TlsDetectFail(TlsLayer):

    def _establish_tls_with_client(self):
        log = False
        try:
            log = valid_conn(self.client_conn.address[1])
            super()._establish_tls_with_client()
        except TlsProtocolException as e:
            addr, sni = self.server_conn.ip_address, self.server_conn.sni
            if sni is not None:
                #It saves pinning that potentially belong to the app (it is necessary to fix a race condition)
                log_data((False, sni, addr), datap)
            if log:
                #addr, sni = self.server_conn.ip_address, self.server_conn.sni
                log_data((False, sni, addr), dataf)
            raise e

class Interceptor:

    # When the addon is loaded adds a new option
    def load(self, loader):
        loader.add_option(
                name = "app",
                typespec = str,
                default = "com.android.chrome",
                help = "App to be examined",
        )

    # Configure the command when the app
    # option is modified.
    def configure(self, updated):
        global command
        if ctx.options.app:
            app = ctx.options.app
            command = "adb shell 'su -c netstat -utpn' | grep " + validate(app) + " | sort -u | tr -s ' ' | cut -d ' ' -f 4"

    # Replace next layer in client TLS
    # Handshake to detect failures.
    def next_layer(self, nlayer):
        if isinstance(nlayer, TlsLayer) and nlayer._client_tls:
            nlayer.__class__ = TlsDetectFail

    # For each request checks if it belongs to our app
    # and logs it if neccessary.
    def request(self, flow):
        port, host = conn_data(flow.client_conn, flow.request)
        if valid_conn(port):
            log_data((True, host, flow.request), dataf)

###########################################################################################################################
#                                                                                                                         #
#                                       Utils                                                                             #
#                                                                                                                         #
###########################################################################################################################

# Logs a an entry to a selected datafile
def log_data(entry, dataf):
    with open(dataf, "ab") as f:
        pickle.dump(entry, f)

# Checks if connection is from the specified app
def valid_conn(port):
    nets = call_sh(command).splitlines()
    ports = app_ports(nets)
    #if not ports:
       # logger.warning("High number of empty app connections: check if adb connection has root permissions", extra={'apk': ctx.options.app})
    return port in ports

# Returns client port and server domain
# of a HTTP connection.
def conn_data(client, req):
    port = client.address[1]
    host = get_host(client, req)
    return (port, host)

# Gets host from SNI or header information.
def get_host(client, req):
    if client.sni:
        return client.sni
    elif "Host" in req.headers:
        return req.headers["Host"]
    elif "host" in req.headers:
        return req.headers["host"]
    else:
        return "unknown"

# Returns a list of every port of a connection
# of the selected app
def app_ports(nets):
    return [int(l.split(":")[-1]) for l in nets]

# Remove all characters in the app package name that are not dots or alphanumeric.
# Important to avoid vulnerabilities.
def validate(app):
    return "".join([c for c in app if c == "." or c.isalnum()])

# Executes a command in a shell and returns its output
def call_sh(command):
    return sub.run(command, shell=True, stdout=sub.PIPE, stderr=sub.PIPE).stdout.decode("utf-8")

addons = [Interceptor()]
