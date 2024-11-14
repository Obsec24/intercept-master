# Pinning

Install, configure and run Frida to bypass pinning implementation. Add new cases in `pinning_cases.js`.

## Install and configure
```
pinning.sh <target apk> <apk name>

```

## Run
```
frida -U -l intercept/pinning/pinning_cases.js -f <apk name> --no-pause

```

## Notes

- Frida X86_64 is used in the AndroidX86 emulator, while Frida ARM64 is used in the physical device. Use the command `adb shell getprop ro.product.cpu.abi` to get the CPU device/emulator architecture.
