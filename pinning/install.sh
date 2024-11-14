#!/bin/sh

# Remount the data partition in read-write mode to write Frida.
#mount -o rw,remount /data

# Copy Frida server to the device
cp /sdcard/frida-server /data/local/frida-server

# Change the permissions of Frida Server
chmod 755 /data/local/frida-server
