ARCH ?= riscv64
DOCKER_NAME ?= docker.educg.net/cg/os-contest:20250516
ifeq ($(ARCH), riscv64)
	KERNEL_BIN := kernel-rv
	KERNEL_ELF := os/target/riscv64gc-unknown-none-elf/release/os
	FS_IMG := sdcard-rv.img
	GDB_ARCH := riscv:rv64
	GDB := gdb-multiarch
else ifeq ($(ARCH), loongarch64)
	KERNEL_BIN := kernel-la
	KERNEL_ELF := os/target/loongarch64-unknown-none/release/os
	FS_IMG := sdcard-la.img
	GDB_ARCH := loongarch
	GDB := loongarch64-unknown-linux-gnu-gdb
else
  	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif

GDB_PORT := 1234

.PHONY: docker build_docker all gdbserver gdb gdb-connect gdb-auto

docker:
	docker run -it -v .:/code --entrypoint bash -w /code --privileged ${DOCKER_NAME}

build_docker: 
	docker build -t ${DOCKER_NAME} .

# all:
# 	@cd user && make build ARCH=riscv64
# 	@cd os && make build ARCH=riscv64
# 	@cd user && make build ARCH=loongarch64
# 	@cd os && make build ARCH=loongarch64
# 	@cp ./os/target/riscv64gc-unknown-none-elf/release/os ./kernel-rv
# 	@cp ./os/target/loongarch64-unknown-none/release/os ./kernel-la

# all:
# 	@cd user && make build ARCH=riscv64
# 	@cd os && make build ARCH=riscv64
# 	@cp ./os/target/riscv64gc-unknown-none-elf/release/os ./kernel-rv

all:
	@cd user && make build ARCH=loongarch64
	@cd os && make build ARCH=loongarch64
	@cp ./os/target/loongarch64-unknown-none/release/os ./kernel-la

clean:
	@cd ./os && make clean
	@cd ./user && make clean

# QEMU run configuration
QEMU_DEBUG_FLAGS = -s -S
ifeq ($(ARCH), riscv64)
QEMU_EXEC = qemu-system-riscv64 -machine virt -kernel ${KERNEL_BIN} -m 1G -nographic \
            -smp 1 -bios default -drive file=${FS_IMG},if=none,format=raw,id=x0 \
            -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -no-reboot
else ifeq ($(ARCH), loongarch64)
QEMU_EXEC = qemu-system-loongarch64 -kernel ${KERNEL_BIN} -m 1G -nographic -smp 1 \
            -drive file=${FS_IMG},if=none,format=raw,id=x0 \
            -device virtio-blk-pci,drive=x0 -no-reboot
endif

run: clean all
	${QEMU_EXEC}

# GDB debugging targets
gdbserver: all
	${QEMU_EXEC} ${QEMU_DEBUG_FLAGS}

gdb: all
	@echo "Launching QEMU GDB server in background..."
	@${QEMU_EXEC} ${QEMU_DEBUG_FLAGS} & 
	@sleep 1
	@echo "Starting GDB client..."
	@${GDB} ${KERNEL_ELF} -ex "target remote :${GDB_PORT}" \
        -ex "set arch ${GDB_ARCH}" \
        -ex "b rust_main" \
        -ex "continue"

gdb-connect:
	@echo "Connecting to QEMU GDB server at :${GDB_PORT}"
	@${GDB} ${KERNEL_ELF} -ex "target remote :${GDB_PORT}" \
        -ex "set arch ${GDB_ARCH}"

gdb-auto: all
	@echo "Starting tmux session for OS debugging..."
	@tmux new-session -d -s os-debug-session \
		"${QEMU_EXEC} ${QEMU_DEBUG_FLAGS}; echo 'QEMU exited with status $$?'; read -p 'Press Enter to close this window'"
	@tmux split-window -h -t os-debug-session \
		"${GDB} -q -ex 'file ${KERNEL_ELF}' -ex 'set arch ${GDB_ARCH}' -ex 'target remote :${GDB_PORT}' -ex 'b main' -ex 'c'; echo 'GDB exited with status $$?'; read -p 'Press Enter to close this window'"
	@tmux attach-session -t os-debug-session

modify:
	@cp ${HOME}/sdcard-rv.img  ${HOME}/osrepo/sdcard-rv.img

disasm:
	@cd os && make disasm ARCH=loongarch64 LOG=DEBUG