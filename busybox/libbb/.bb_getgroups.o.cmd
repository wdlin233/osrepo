cmd_libbb/bb_getgroups.o := loongarch64-linux-gnu-gcc -static -Wp,-MD,libbb/.bb_getgroups.o.d  -std=gnu99 -Iinclude -Ilibbb  -include include/autoconf.h -D_GNU_SOURCE -DNDEBUG -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DBB_VER='"1.33.1"' -Wall -Wshadow -Wwrite-strings -Wundef -Wstrict-prototypes -Wunused -Wunused-parameter -Wunused-function -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wno-format-security -Wdeclaration-after-statement -Wold-style-definition -finline-limit=0 -fno-builtin-strlen -fomit-frame-pointer -ffunction-sections -fdata-sections -fno-guess-branch-probability -funsigned-char -static-libgcc -falign-functions=1 -falign-jumps=1 -falign-labels=1 -falign-loops=1 -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-builtin-printf -g -O0    -DKBUILD_BASENAME='"bb_getgroups"'  -DKBUILD_MODNAME='"bb_getgroups"' -c -o libbb/bb_getgroups.o libbb/bb_getgroups.c

deps_libbb/bb_getgroups.o := \
  libbb/bb_getgroups.c \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/stdc-predef.h \
  include/libbb.h \
    $(wildcard include/config/feature/shadowpasswds.h) \
    $(wildcard include/config/use/bb/shadow.h) \
    $(wildcard include/config/selinux.h) \
    $(wildcard include/config/feature/utmp.h) \
    $(wildcard include/config/locale/support.h) \
    $(wildcard include/config/use/bb/pwd/grp.h) \
    $(wildcard include/config/lfs.h) \
    $(wildcard include/config/feature/buffers/go/on/stack.h) \
    $(wildcard include/config/feature/buffers/go/in/bss.h) \
    $(wildcard include/config/variable/arch/pagesize.h) \
    $(wildcard include/config/feature/verbose.h) \
    $(wildcard include/config/feature/etc/services.h) \
    $(wildcard include/config/feature/ipv6.h) \
    $(wildcard include/config/feature/seamless/xz.h) \
    $(wildcard include/config/feature/seamless/lzma.h) \
    $(wildcard include/config/feature/seamless/bz2.h) \
    $(wildcard include/config/feature/seamless/gz.h) \
    $(wildcard include/config/feature/seamless/z.h) \
    $(wildcard include/config/float/duration.h) \
    $(wildcard include/config/feature/check/names.h) \
    $(wildcard include/config/feature/prefer/applets.h) \
    $(wildcard include/config/long/opts.h) \
    $(wildcard include/config/feature/pidfile.h) \
    $(wildcard include/config/feature/syslog.h) \
    $(wildcard include/config/feature/syslog/info.h) \
    $(wildcard include/config/warn/simple/msg.h) \
    $(wildcard include/config/feature/individual.h) \
    $(wildcard include/config/ash.h) \
    $(wildcard include/config/sh/is/ash.h) \
    $(wildcard include/config/bash/is/ash.h) \
    $(wildcard include/config/hush.h) \
    $(wildcard include/config/sh/is/hush.h) \
    $(wildcard include/config/bash/is/hush.h) \
    $(wildcard include/config/echo.h) \
    $(wildcard include/config/printf.h) \
    $(wildcard include/config/test.h) \
    $(wildcard include/config/test1.h) \
    $(wildcard include/config/test2.h) \
    $(wildcard include/config/kill.h) \
    $(wildcard include/config/killall.h) \
    $(wildcard include/config/killall5.h) \
    $(wildcard include/config/chown.h) \
    $(wildcard include/config/ls.h) \
    $(wildcard include/config/xxx.h) \
    $(wildcard include/config/route.h) \
    $(wildcard include/config/feature/hwib.h) \
    $(wildcard include/config/desktop.h) \
    $(wildcard include/config/feature/crond/d.h) \
    $(wildcard include/config/feature/setpriv/capabilities.h) \
    $(wildcard include/config/run/init.h) \
    $(wildcard include/config/feature/securetty.h) \
    $(wildcard include/config/pam.h) \
    $(wildcard include/config/use/bb/crypt.h) \
    $(wildcard include/config/feature/adduser/to/group.h) \
    $(wildcard include/config/feature/del/user/from/group.h) \
    $(wildcard include/config/ioctl/hex2str/error.h) \
    $(wildcard include/config/feature/editing.h) \
    $(wildcard include/config/feature/editing/history.h) \
    $(wildcard include/config/feature/tab/completion.h) \
    $(wildcard include/config/shell/ash.h) \
    $(wildcard include/config/shell/hush.h) \
    $(wildcard include/config/feature/editing/savehistory.h) \
    $(wildcard include/config/feature/username/completion.h) \
    $(wildcard include/config/feature/editing/vi.h) \
    $(wildcard include/config/feature/editing/save/on/exit.h) \
    $(wildcard include/config/pmap.h) \
    $(wildcard include/config/feature/show/threads.h) \
    $(wildcard include/config/feature/ps/additional/columns.h) \
    $(wildcard include/config/feature/topmem.h) \
    $(wildcard include/config/feature/top/smp/process.h) \
    $(wildcard include/config/pgrep.h) \
    $(wildcard include/config/pkill.h) \
    $(wildcard include/config/pidof.h) \
    $(wildcard include/config/sestatus.h) \
    $(wildcard include/config/unicode/support.h) \
    $(wildcard include/config/feature/mtab/support.h) \
    $(wildcard include/config/feature/clean/up.h) \
    $(wildcard include/config/feature/devfs.h) \
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
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/ctype.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/locale_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/__locale_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/dirent.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/dirent.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/dirent_ext.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/errno.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/errno.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/linux/errno.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm/errno.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm-generic/errno.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm-generic/errno-base.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/error_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/fcntl.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/fcntl.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/fcntl-linux.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct_iovec.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/linux/falloc.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct_timespec.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/time_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/stat.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/struct_stat.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/inttypes.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/netdb.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/netinet/in.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/socket.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/socket.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/types.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/clock_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/clockid_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/timer_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/select.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/select.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/sigset_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/__sigset_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct_timeval.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/pthreadtypes.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/thread-shared-types.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/pthreadtypes-arch.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/atomic_wide_counter.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/struct_mutex.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/struct_rwlock.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/socket_type.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/sockaddr.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm/socket.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm-generic/socket.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/linux/posix_types.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/linux/stddef.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm/posix_types.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm-generic/posix_types.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm/bitsperlong.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm-generic/bitsperlong.h \
    $(wildcard include/config/64bit.h) \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm/sockios.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm-generic/sockios.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct_osockaddr.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/in.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/rpc/netdb.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/sigevent_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/__sigval_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/netdb.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/setjmp.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/setjmp.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct___jmp_buf_tag.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/signal.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/signum-generic.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/signum-arch.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/sig_atomic_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/siginfo_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/siginfo-arch.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/siginfo-consts.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/siginfo-consts-arch.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/sigval_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/sigevent-consts.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/sigaction.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/sigcontext.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm/sigcontext.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/linux/types.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm/types.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm-generic/types.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm-generic/int-ll64.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/stack_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/ucontext.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/sigstack.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/sigstksz.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/ss_flags.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct_sigstack.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/sigthread.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/signal_ext.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/paths.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/stdio.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/lib/gcc/loongarch64-linux-gnu/13.2.0/include/stdarg.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/__fpos_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/__mbstate_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/__fpos64_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/__FILE.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/FILE.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct_FILE.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/cookie_io_functions_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/stdio_lim.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/floatn.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/floatn-common.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/stdlib.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/waitflags.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/waitstatus.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/alloca.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/stdlib-float.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/string.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/strings.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/libgen.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/poll.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/poll.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/poll.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/ioctl.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/ioctls.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm/ioctls.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm-generic/ioctls.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/linux/ioctl.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm/ioctl.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm-generic/ioctl.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/ioctl-types.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/ttydefaults.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/mman.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/mman.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/mman-map-flags-generic.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/mman-linux.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/mman-shared.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/mman_ext.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/resource.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/resource.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct_rusage.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/stat.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/statx.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/linux/stat.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/statx-generic.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct_statx_timestamp.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct_statx.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/time.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/sysmacros.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/sysmacros.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/wait.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/idtype_t.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/termios.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/termios.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/termios-struct.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/termios-c_cc.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/termios-c_iflag.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/termios-c_oflag.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/termios-baud.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/termios-c_cflag.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/termios-c_lflag.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/termios-tcflow.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/termios-misc.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/time.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/time.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/timex.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct_tm.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/types/struct_itimerspec.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/param.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/param.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/linux/param.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm/param.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/asm-generic/param.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/pwd.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/grp.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/mntent.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/sys/statfs.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/statfs.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/utmp.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/utmp.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/utmpx.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/bits/utmpx.h \
  /opt/gcc-13.2.0-loongarch64-linux-gnu/sysroot/usr/include/arpa/inet.h \
  include/pwd_.h \
  include/grp_.h \
  include/shadow_.h \
  include/xatonum.h \

libbb/bb_getgroups.o: $(deps_libbb/bb_getgroups.o)

$(deps_libbb/bb_getgroups.o):
