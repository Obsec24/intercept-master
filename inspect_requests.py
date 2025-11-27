#!/usr/bin/python3

import pickle
import subprocess as sub
import importlib.util

from mitmproxy import http, ctx

dataf = "output.log"
datap = "pinning.log"
command = ""

LOG_FILE = "/app/logging/log/operation.privapp.log"
HELPER_JSON_LOGGER = '/app/logging-master/agent/helper/log.py'

# Load logger properly
spec = importlib.util.spec_from_file_location("log", HELPER_JSON_LOGGER)
log_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(log_module)
logger = log_module.init_logger(LOG_FILE)

# ------------ UTILS  ------------

def log_data(entry, dataf):
    with open(dataf, "ab") as f:
        pickle.dump(entry, f)

def validate(app):
    return "".join([c for c in app if c == "." or c.isalnum()])

def call_sh(command):
    return sub.run(command, shell=True, stdout=sub.PIPE,
                   stderr=sub.PIPE).stdout.decode("utf-8")

def app_ports(nets):
    ports = []
    for l in nets:
        try:
            ports.append(int(l.split(":")[-1]))
        except:
            pass
    return ports

def valid_conn(port):
    # Si app=ALL capturar TODO
    if ctx.options.app == "ALL":
        return True

    nets = call_sh(command).splitlines()
    ports = app_ports(nets)
    return port in ports

def get_host(flow):
    if flow.server_conn.sni:
        return flow.server_conn.sni
    return flow.request.pretty_host

# ------------ MAIN ADDON ------------

class Interceptor:

    def load(self, loader):
        loader.add_option(
            name="app",
            typespec=str,
            default="com.android.chrome",
            help="App to inspect"
        )

    def configure(self, updated):
        global command

        if ctx.options.app == "ALL":
            command = "adb shell 'su -c netstat -utpn' | tr -s ' ' | cut -d ' ' -f 4"
            return

        if ctx.options.app:
            app = ctx.options.app
            command = (
                "adb shell 'su -c netstat -utpn' | grep " +
                validate(app) +
                " | tr -s ' ' | cut -d ' ' -f 4"
            )

    # HTTP requests
    def request(self, flow: http.HTTPFlow):
        port = flow.client_conn.address[1]
        host = get_host(flow)

        if valid_conn(port):

            # ----- SERIALIZACIÓN SEGURA -----
            req_obj = (
                True,
                host,
                {
                    "content": flow.request.content,
                    "path": flow.request.path,
                    "url": flow.request.pretty_url,
                    "host": host,
                    "port": port,
                    "method": flow.request.method,
                    "headers": dict(flow.request.headers)
                }
            )
            # --------------------------------

            log_data(req_obj, dataf)

    # TLS handshake errors (pinning or invalid cert)
    def tls_error(self, flow):
        sni = flow.server_conn.sni or "unknown"
        addr = flow.server_conn.address

        # LOG para archivo pinning.log
        log_data((False, sni, addr), datap)

        port = flow.client_conn.address[1]
        if valid_conn(port):

            # ----- SERIALIZACIÓN SEGURA PARA PINNING -----
            req_obj = (
                False,
                sni,
                {
                    "host": sni,
                    "port": addr[1]
                }
            )
            # ---------------------------------------------

            log_data(req_obj, dataf)


addons = [Interceptor()]
