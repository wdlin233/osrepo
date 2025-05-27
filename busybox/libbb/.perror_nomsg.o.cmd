cmd_libbb/perror_nomsg.o := loongarch64-linux-gnu-gcc -static -Wp,-MD,libbb/.perror_nomsg.o.d  -std=gnu99 -Iinclude -Ilibbb  -include include/autoconf.h -D_GNU_SOURCE -DNDEBUG -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DBB_VER='"1.33.1"' -Wall -Wshadow -Wwrite-strings -Wundef -Wstrict-prototypes -Wunused -Wunused-parameter -Wunused-function -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wno-format-security -Wdeclaration-after-statement -Wold-style-definition -finline-limit=0 -fno-builtin-strlen -fomit-frame-pointer -ffunction-sections -fdata-sections -fno-guess-branch-probability -funsigned-char -static-libgcc -falign-functions=1 -falign-jumps=1 -falign-labels=1 -falign-loops=1 -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-builtin-printf -g -O0    -DKBUILD_BASENAME='"perror_nomsg"'  -DKBUILD_MODNAME='"perror_nomsg"' -c -o libbb/perror_nomsg.o libbb/perror_nomsg.c

deps_libbb/perror_nomsg.o := \
  libbb/perror_nomsg.c \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/stdc-predef.h \
  include/platform.h \
    $(wildcard include/config/werror.h) \
    $(wildcard include/config/big/endian.h) \
    $(wildcard include/config/little/endian.h) \
    $(wildcard include/config/nommu.h) \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/lib/gcc/loongarch64-linux-gnu/13.2.0/include/limits.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/lib/gcc/loongarch64-linux-gnu/13.2.0/include/syslimits.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/limits.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/libc-header-start.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/features.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/features-time64.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/wordsize.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/timesize.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/cdefs.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/long-double.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/gnu/stubs.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/gnu/stubs-lp64d.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/posix1_lim.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/local_lim.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/linux/limits.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/pthread_stack_min-dynamic.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/posix2_lim.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/xopen_lim.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/uio_lim.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/byteswap.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/byteswap.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/typesizes.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/time64.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/endian.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/endian.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/endianness.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/uintn-identity.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/lib/gcc/loongarch64-linux-gnu/13.2.0/include/stdint.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/stdint.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/wchar.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/stdint-intn.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/stdint-uintn.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/lib/gcc/loongarch64-linux-gnu/13.2.0/include/stdbool.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/unistd.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/posix_opt.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/environments.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/lib/gcc/loongarch64-linux-gnu/13.2.0/include/stddef.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/confname.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/getopt_posix.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/getopt_core.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/unistd_ext.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/linux/close_range.h \

libbb/perror_nomsg.o: $(deps_libbb/perror_nomsg.o)

$(deps_libbb/perror_nomsg.o):
