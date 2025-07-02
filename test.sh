busybox echo "run time test"
cd musl
./basic_testcode.sh
./busybox_testcode.sh
cd ..
cd glibc
./basic_testcode.sh
./busybox_testcode.sh

