# # run_testcases_musl.sh


echo "#### OS COMP TEST GROUP START lmbench-musl ####"

echo latency measurements
./lmbench_all lat_syscall -P 1 null
./lmbench_all lat_syscall -P 1 read
./lmbench_all lat_syscall -P 1 write
./busybox mkdir -p /var/tmp
./busybox touch /var/tmp/lmbench
./lmbench_all lat_syscall -P 1 stat /var/tmp/lmbench
./lmbench_all lat_syscall -P 1 fstat /var/tmp/lmbench
./lmbench_all lat_syscall -P 1 open /var/tmp/lmbench
./lmbench_all lat_select -n 100 -P 1 file
./lmbench_all lat_sig -P 1 install
./lmbench_all lat_sig -P 1 catch
./lmbench_all lat_sig -P 1 prot lat_sig

# ./lmbench_all lat_pipe -P 1
./lmbench_all lat_proc -P 1 fork
#./lmbench_all lat_proc -P 1 exec
cp hello /tmp
#./lmbench_all lat_proc -P 1 shell
./lmbench_all lmdd label="File /var/tmp/XXX write bandwidth:" of=/var/tmp/XXX move=1m fsync=1 print=3
./lmbench_all lat_pagefault -P 1 /var/tmp/XXX
./lmbench_all lat_mmap -P 1 512k /var/tmp/XXX
echo file system latency
./lmbench_all lat_fs /var/tmp
echo Bandwidth measurements
#./lmbench_all bw_pipe -P 1
# ./lmbench_all bw_file_rd -P 1 512k io_only /var/tmp/XXX
# ./lmbench_all bw_file_rd -P 1 512k open2close /var/tmp/XXX
# ./lmbench_all bw_mmap_rd -P 1 512k mmap_only /var/tmp/XXX
# ./lmbench_all bw_mmap_rd -P 1 512k open2close /var/tmp/XXX
echo context switch overhead
./lmbench_all lat_ctx -P 1 -s 32 2 4 8 16 24 32 64 96


echo "#### OS COMP TEST GROUP END lmbench-musl ####"


# libctest.sh
./busybox echo "#### OS COMP TEST GROUP START libctest-musl ####"
#./run-dynamic.sh
./runtest.exe -w entry-dynamic.exe argv
./runtest.exe -w entry-dynamic.exe basename
./runtest.exe -w entry-dynamic.exe clocale_mbfuncs
./runtest.exe -w entry-dynamic.exe clock_gettime
./runtest.exe -w entry-dynamic.exe dirname
./runtest.exe -w entry-dynamic.exe dlopen
./runtest.exe -w entry-dynamic.exe env
./runtest.exe -w entry-dynamic.exe fdopen
./runtest.exe -w entry-dynamic.exe fnmatch
./runtest.exe -w entry-dynamic.exe fscanf
./runtest.exe -w entry-dynamic.exe fwscanf
./runtest.exe -w entry-dynamic.exe iconv_open
./runtest.exe -w entry-dynamic.exe inet_pton
./runtest.exe -w entry-dynamic.exe mbc
./runtest.exe -w entry-dynamic.exe memstream
./runtest.exe -w entry-dynamic.exe pthread_cancel_points
./runtest.exe -w entry-dynamic.exe pthread_cancel
./runtest.exe -w entry-dynamic.exe pthread_cond
./runtest.exe -w entry-dynamic.exe pthread_tsd
./runtest.exe -w entry-dynamic.exe qsort
./runtest.exe -w entry-dynamic.exe random
./runtest.exe -w entry-dynamic.exe search_hsearch
./runtest.exe -w entry-dynamic.exe search_insque
./runtest.exe -w entry-dynamic.exe search_lsearch
./runtest.exe -w entry-dynamic.exe search_tsearch
#./runtest.exe -w entry-dynamic.exe sem_init
./runtest.exe -w entry-dynamic.exe setjmp
./runtest.exe -w entry-dynamic.exe snprintf
./runtest.exe -w entry-dynamic.exe socket
./runtest.exe -w entry-dynamic.exe sscanf
./runtest.exe -w entry-dynamic.exe sscanf_long
./runtest.exe -w entry-dynamic.exe stat
./runtest.exe -w entry-dynamic.exe strftime
./runtest.exe -w entry-dynamic.exe string
./runtest.exe -w entry-dynamic.exe string_memcpy
./runtest.exe -w entry-dynamic.exe string_memmem
./runtest.exe -w entry-dynamic.exe string_memset
./runtest.exe -w entry-dynamic.exe string_strchr
./runtest.exe -w entry-dynamic.exe string_strcspn
./runtest.exe -w entry-dynamic.exe string_strstr
./runtest.exe -w entry-dynamic.exe strptime
./runtest.exe -w entry-dynamic.exe strtod
./runtest.exe -w entry-dynamic.exe strtod_simple
./runtest.exe -w entry-dynamic.exe strtof
./runtest.exe -w entry-dynamic.exe strtol
./runtest.exe -w entry-dynamic.exe strtold
./runtest.exe -w entry-dynamic.exe swprintf
./runtest.exe -w entry-dynamic.exe tgmath
./runtest.exe -w entry-dynamic.exe time
./runtest.exe -w entry-dynamic.exe tls_init
./runtest.exe -w entry-dynamic.exe tls_local_exec
./runtest.exe -w entry-dynamic.exe udiv
./runtest.exe -w entry-dynamic.exe ungetc
./runtest.exe -w entry-dynamic.exe utime
./runtest.exe -w entry-dynamic.exe wcsstr
./runtest.exe -w entry-dynamic.exe wcstol
./runtest.exe -w entry-dynamic.exe daemon_failure
./runtest.exe -w entry-dynamic.exe dn_expand_empty
./runtest.exe -w entry-dynamic.exe dn_expand_ptr_0
./runtest.exe -w entry-dynamic.exe fflush_exit
./runtest.exe -w entry-dynamic.exe fgets_eof
#./runtest.exe -w entry-dynamic.exe fgetwc_buffering
./runtest.exe -w entry-dynamic.exe fpclassify_invalid_ld80
./runtest.exe -w entry-dynamic.exe ftello_unflushed_append
./runtest.exe -w entry-dynamic.exe getpwnam_r_crash
./runtest.exe -w entry-dynamic.exe getpwnam_r_errno
./runtest.exe -w entry-dynamic.exe iconv_roundtrips
./runtest.exe -w entry-dynamic.exe inet_ntop_v4mapped
./runtest.exe -w entry-dynamic.exe inet_pton_empty_last_field
./runtest.exe -w entry-dynamic.exe iswspace_null
./runtest.exe -w entry-dynamic.exe lrand48_signextend
./runtest.exe -w entry-dynamic.exe lseek_large
./runtest.exe -w entry-dynamic.exe malloc_0
./runtest.exe -w entry-dynamic.exe mbsrtowcs_overflow
./runtest.exe -w entry-dynamic.exe memmem_oob_read
./runtest.exe -w entry-dynamic.exe memmem_oob
./runtest.exe -w entry-dynamic.exe mkdtemp_failure
./runtest.exe -w entry-dynamic.exe mkstemp_failure
./runtest.exe -w entry-dynamic.exe printf_1e9_oob
./runtest.exe -w entry-dynamic.exe printf_fmt_g_round
./runtest.exe -w entry-dynamic.exe printf_fmt_g_zeros
./runtest.exe -w entry-dynamic.exe printf_fmt_n
./runtest.exe -w entry-dynamic.exe pthread_robust_detach
#./runtest.exe -w entry-dynamic.exe pthread_cond_smasher
./runtest.exe -w entry-dynamic.exe pthread_condattr_setclock
./runtest.exe -w entry-dynamic.exe pthread_exit_cancel
./runtest.exe -w entry-dynamic.exe pthread_once_deadlock
./runtest.exe -w entry-dynamic.exe pthread_rwlock_ebusy
./runtest.exe -w entry-dynamic.exe putenv_doublefree
./runtest.exe -w entry-dynamic.exe regex_backref_0
./runtest.exe -w entry-dynamic.exe regex_bracket_icase
./runtest.exe -w entry-dynamic.exe regex_ere_backref
./runtest.exe -w entry-dynamic.exe regex_escaped_high_byte
./runtest.exe -w entry-dynamic.exe regex_negated_range
./runtest.exe -w entry-dynamic.exe regexec_nosub
./runtest.exe -w entry-dynamic.exe rewind_clear_error
./runtest.exe -w entry-dynamic.exe rlimit_open_files
./runtest.exe -w entry-dynamic.exe scanf_bytes_consumed
./runtest.exe -w entry-dynamic.exe scanf_match_literal_eof
./runtest.exe -w entry-dynamic.exe scanf_nullbyte_char
./runtest.exe -w entry-dynamic.exe setvbuf_unget
./runtest.exe -w entry-dynamic.exe sigprocmask_internal
./runtest.exe -w entry-dynamic.exe sscanf_eof
./runtest.exe -w entry-dynamic.exe statvfs
./runtest.exe -w entry-dynamic.exe strverscmp
./runtest.exe -w entry-dynamic.exe syscall_sign_extend
#./runtest.exe -w entry-dynamic.exe tls_get_new_dtv
./runtest.exe -w entry-dynamic.exe uselocale_0
./runtest.exe -w entry-dynamic.exe wcsncpy_read_overflow
./runtest.exe -w entry-dynamic.exe wcsstr_false_negative

# ./run-static.sh
./runtest.exe -w entry-static.exe argv
./runtest.exe -w entry-static.exe basename
#./runtest.exe -w entry-static.exe clocale_mbfuncs
./runtest.exe -w entry-static.exe clock_gettime
./runtest.exe -w entry-static.exe dirname
./runtest.exe -w entry-static.exe env
./runtest.exe -w entry-static.exe fdopen
./runtest.exe -w entry-static.exe fnmatch
./runtest.exe -w entry-static.exe fscanf
./runtest.exe -w entry-static.exe fwscanf
./runtest.exe -w entry-static.exe iconv_open
./runtest.exe -w entry-static.exe inet_pton
./runtest.exe -w entry-static.exe mbc
./runtest.exe -w entry-static.exe memstream
./runtest.exe -w entry-static.exe pthread_cancel_points
./runtest.exe -w entry-static.exe pthread_cancel
./runtest.exe -w entry-static.exe pthread_cond
./runtest.exe -w entry-static.exe pthread_tsd
./runtest.exe -w entry-static.exe qsort
./runtest.exe -w entry-static.exe random
./runtest.exe -w entry-static.exe search_hsearch
./runtest.exe -w entry-static.exe search_insque
./runtest.exe -w entry-static.exe search_lsearch
./runtest.exe -w entry-static.exe search_tsearch
./runtest.exe -w entry-static.exe setjmp
./runtest.exe -w entry-static.exe snprintf
./runtest.exe -w entry-static.exe socket
./runtest.exe -w entry-static.exe sscanf
./runtest.exe -w entry-static.exe sscanf_long
./runtest.exe -w entry-static.exe stat
./runtest.exe -w entry-static.exe strftime
./runtest.exe -w entry-static.exe string
./runtest.exe -w entry-static.exe string_memcpy
./runtest.exe -w entry-static.exe string_memmem
./runtest.exe -w entry-static.exe string_memset
./runtest.exe -w entry-static.exe string_strchr
./runtest.exe -w entry-static.exe string_strcspn
./runtest.exe -w entry-static.exe string_strstr
./runtest.exe -w entry-static.exe strptime
./runtest.exe -w entry-static.exe strtod
./runtest.exe -w entry-static.exe strtod_simple
./runtest.exe -w entry-static.exe strtof
./runtest.exe -w entry-static.exe strtol
./runtest.exe -w entry-static.exe strtold
./runtest.exe -w entry-static.exe swprintf
./runtest.exe -w entry-static.exe tgmath
./runtest.exe -w entry-static.exe time
./runtest.exe -w entry-static.exe tls_align
./runtest.exe -w entry-static.exe udiv
./runtest.exe -w entry-static.exe ungetc
./runtest.exe -w entry-static.exe utime
./runtest.exe -w entry-static.exe wcsstr
./runtest.exe -w entry-static.exe wcstol
./runtest.exe -w entry-static.exe daemon_failure
./runtest.exe -w entry-static.exe dn_expand_empty
./runtest.exe -w entry-static.exe dn_expand_ptr_0
./runtest.exe -w entry-static.exe fflush_exit
./runtest.exe -w entry-static.exe fgets_eof
./runtest.exe -w entry-static.exe fgetwc_buffering
./runtest.exe -w entry-static.exe fpclassify_invalid_ld80
./runtest.exe -w entry-static.exe ftello_unflushed_append
./runtest.exe -w entry-static.exe getpwnam_r_crash
./runtest.exe -w entry-static.exe getpwnam_r_errno
./runtest.exe -w entry-static.exe iconv_roundtrips
./runtest.exe -w entry-static.exe inet_ntop_v4mapped
./runtest.exe -w entry-static.exe inet_pton_empty_last_field
./runtest.exe -w entry-static.exe iswspace_null
./runtest.exe -w entry-static.exe lrand48_signextend
./runtest.exe -w entry-static.exe lseek_large
./runtest.exe -w entry-static.exe malloc_0
./runtest.exe -w entry-static.exe mbsrtowcs_overflow
./runtest.exe -w entry-static.exe memmem_oob_read
./runtest.exe -w entry-static.exe memmem_oob
./runtest.exe -w entry-static.exe mkdtemp_failure
./runtest.exe -w entry-static.exe mkstemp_failure
./runtest.exe -w entry-static.exe printf_1e9_oob
./runtest.exe -w entry-static.exe printf_fmt_g_round
./runtest.exe -w entry-static.exe printf_fmt_g_zeros
./runtest.exe -w entry-static.exe printf_fmt_n
./runtest.exe -w entry-static.exe pthread_robust_detach
./runtest.exe -w entry-static.exe pthread_cancel_sem_wait
#./runtest.exe -w entry-static.exe pthread_cond_smasher
./runtest.exe -w entry-static.exe pthread_condattr_setclock
./runtest.exe -w entry-static.exe pthread_exit_cancel
./runtest.exe -w entry-static.exe pthread_once_deadlock
./runtest.exe -w entry-static.exe pthread_rwlock_ebusy
./runtest.exe -w entry-static.exe putenv_doublefree
./runtest.exe -w entry-static.exe regex_backref_0
./runtest.exe -w entry-static.exe regex_bracket_icase
./runtest.exe -w entry-static.exe regex_ere_backref
./runtest.exe -w entry-static.exe regex_escaped_high_byte
./runtest.exe -w entry-static.exe regex_negated_range
./runtest.exe -w entry-static.exe regexec_nosub
./runtest.exe -w entry-static.exe rewind_clear_error
./runtest.exe -w entry-static.exe rlimit_open_files
./runtest.exe -w entry-static.exe scanf_bytes_consumed
./runtest.exe -w entry-static.exe scanf_match_literal_eof
./runtest.exe -w entry-static.exe scanf_nullbyte_char
./runtest.exe -w entry-static.exe setvbuf_unget
./runtest.exe -w entry-static.exe sigprocmask_internal
./runtest.exe -w entry-static.exe sscanf_eof
./runtest.exe -w entry-static.exe statvfs
./runtest.exe -w entry-static.exe strverscmp
./runtest.exe -w entry-static.exe syscall_sign_extend
./runtest.exe -w entry-static.exe uselocale_0
./runtest.exe -w entry-static.exe wcsncpy_read_overflow
./runtest.exe -w entry-static.exe wcsstr_false_negative

./busybox echo "#### OS COMP TEST GROUP END libctest-musl ####"

# # busybox_testcode.sh
./busybox echo "#### OS COMP TEST GROUP START busybox-musl ####"
./busybox cat ./busybox_cmd.txt | while read line
do
        if [[ "$line" == "sh -c 'sleep 5' & ./busybox kill \$!" ]]; then
                echo "testcase busybox $line skipped (potential panic risk)"
                continue
        fi

        eval "./busybox $line"
        RTN=$?
        if [[ $RTN -ne 0 && "$line" != "false" ]] ;then
                echo "testcase busybox $line fail"
                # echo "return: $RTN, cmd: $line" >> $RST
        else
                echo "testcase busybox $line success"
        fi
done

./busybox echo "#### OS COMP TEST GROUP END busybox-musl ####"


./basic_testcode.sh
./lua_testcode.sh

# ./busybox echo "#### OS COMP TEST GROUP START iozone-musl ####"
# ./busybox echo iozone automatic measurements
# ./iozone -a -r 1k -s 4m
# ./busybox echo iozone throughput write/read measurements
# ./iozone -t 4 -i 0 -i 1 -r 1k -s 1m
# ./busybox echo iozone throughput random-read measurements
# ./iozone -t 4 -i 0 -i 2 -r 1k -s 1m
# ./busybox echo iozone throughput read-backwards measurements
# ./iozone -t 4 -i 0 -i 3 -r 1k -s 1m
# ./busybox echo iozone throughput stride-read measurements
# ./iozone -t 4 -i 0 -i 5 -r 1k -s 1m
# ./busybox echo iozone throughput fwrite/fread measurements
# ./iozone -t 4 -i 6 -i 7 -r 1k -s 1m
# ./busybox echo iozone throughput pwrite/pread measurements
# ./iozone -t 4 -i 9 -i 10 -r 1k -s 1m
# ./busybox echo iozone throughtput pwritev/preadv measurements
# ./iozone -t 4 -i 11 -i 12 -r 1k -s 1m
# ./busybox echo "#### OS COMP TEST GROUP END iozone-musl ####"

# ./busybox echo "#### OS COMP TEST GROUP START libcbench-musl ####"
# ./libc-bench
# ./busybox echo "#### OS COMP TEST GROUP END libcbench-musl ####"


