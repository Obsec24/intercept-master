# Interception tool

## Running

To use the tool run the following command:

```
proxy.sh [-h] [-i <target ip>] [-a <target apk>] [-p <apk package name>]
```

The `-a` and `-p` flags are not compatible, the first one should be used when the application has to be installed and the second one when the application is already installed in the target device. The output of the interception will  be found in the `output.log` file.

