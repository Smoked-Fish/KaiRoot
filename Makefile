# TOOLCHAIN must point at an NDK llvm toolchain root, I used 27.3.13750724
# make TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64

TOOLCHAIN ?= $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64
CLANG     := $(TOOLCHAIN)/bin/clang

.PHONY: all clean

all: kai_root

kai_root: kai_root.c kai_profile.c kai_profile.h exploit/common.h exploit/reclaim.h exploit/select.h exploit/krw.h exploit/stages.h
	$(CLANG) --target=armv7a-linux-androideabi29 -O2 -static -o kai_root kai_root.c kai_profile.c

clean:
	rm -f kai_root
