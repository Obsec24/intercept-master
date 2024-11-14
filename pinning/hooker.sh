#!/bin/sh
if [ $# -ne 1 ]
then
    echo 'Usage: sh $0 <target_ip>'
    return
fi

LOG_FILE='/app/logging/log/operation.privapp.log'

msg=$(adb connect $1)
sh /app/logging/agent/helper/log.sh D "Connecting to device:  $msg" $0 $LOG_FILE
#this version of frida was intentionally selected as others had some bugs
msg=$(adb -s $1 push intercept/pinning/frida-server-12.7.22-android-arm64 /sdcard/frida-server)
sh /app/logging/agent/helper/log.sh D "Copying frida files: $msg" $0 $LOG_FILE
msg=$(adb -s $1 push intercept/pinning/install.sh /sdcard)
sh /app/logging/agent/helper/log.sh D "Copying frida install to sdcard: $msg" $0 $LOG_FILE
msg=$(adb -s $1 shell su -c sh /sdcard/install.sh)
sh /app/logging/agent/helper/log.sh D "Installing frida: $msg" $0 $LOG_FILE
msg=$(adb -s $1 push ~/.mitmproxy/mitmproxy-ca-cert.cer /data/local/tmp/cert-der.cr)
sh /app/logging/agent/helper/log.sh D "Installing mitmproxy certicate: $msg" $0 $LOG_FILE
adb -s $1 shell '/data/local/frida-server &'
