## kai_root

Kernel root for the TCL Flip 3 (Gflip7_VZW / T435S, kernel
4.9.277-perf+, armv7)

Based on [CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499)

Use this at your own risk

### Requirements

`adb shell` access, which can be achieved with jscalated on KaiOS 3.0 devices

### Run

```
adb push kai_root /data/local/tmp/kai_root
adb push profiles /data/local/tmp/profiles
adb shell chmod 755 /data/local/tmp/kai_root
adb shell /data/local/tmp/kai_root
```

The console will tell you if the root succeeds. If it fails, reboot and try again.

`VERBOSE=1 /data/local/tmp/kai_root` will give you more information on why a failure occurred.

### Environment variables

| variable          | default | meaning                               |
|-------------------|---------|---------------------------------------|
| `VERBOSE`         | 0       | per-stage diagnostics on stderr       |
| `ROOT_ATTEMPTS`   | 8       | campaign attempts                     |
| `ROOT_ROUTES`     | 8       | ghost routes per attempt              |
| `ROOT_SPRAY_KB`   | 24576   | initial spray budget                  |
| `ROOT_WORD_SHIFT` | 18      | fd_set word holding the ghost         |
| `ROOT_DELAY_MS`   | 0       | extra delay before the consumer walk  |
| `ROOT_SETTLE_MS`  | 0       | extra settle wait before the campaign |
| `ROOT_BACKOFF_MS` | auto    | fixed backoff between attempts        |
| `ROOT_SAFE`       | 0       | verify the landing, root nothing      |

### Build

Needs an Android NDK (r21+):

```
make TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64
```

### Credits

I used a lot of projects as reference material for this.

* [hazel-cve-2026-43499/tree/main](https://github.com/dorlow/hazel-cve-2026-43499/tree/main)
  The biggest help. ARM32 Linux 4.9, Fire TV
* [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
  First PoC as far as I could tell
* [R0rt1z2/GhostLock-5.10](https://github.com/R0rt1z2/GhostLock-5.10)
* [keyarr/aquaman-pi2055-research](https://github.com/keyarr/aquaman-pi2055-research)