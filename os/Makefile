# Building, riscv64 or loongarch64
ARCH := riscv64
MODE := release

# BOARD
BOARD := qemu

# Building mode argument
ifeq ($(MODE), release)
	MODE_ARG := --release
endif

# KERNEL ENTRY
KERNEL_ENTRY_PA := 0x80200000

# Binutils
OBJDUMP := rust-objdump --arch-name=riscv64
OBJCOPY := rust-objcopy --binary-architecture=riscv64

# Disassembly
DISASM ?= -d

# Tesecases
TESTSUITS := $(wildcard ../testsuits/$(ARCH)/*)
TESTCASES := $(filter-out %.sh %.txt %/mnt, $(TESTSUITS))

ifeq ($(ARCH), riscv64)
  	TARGET := riscv64gc-unknown-none-elf
	KERNEL_ELF := target/$(TARGET)/$(MODE)/os
	KERNEL_BIN := $(KERNEL_ELF).bin
	QEMU_EXEC += qemu-system-$(ARCH) \
				-M 128m \
				-machine virt \
				-kernel $(KERNEL_ELF) \
				-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0
else ifeq ($(ARCH), loongarch64)
  	TARGET := loongarch64-unknown-none
	KERNEL_ELF := target/$(TARGET)/$(MODE)/os
  	QEMU_EXEC += qemu-system-$(ARCH) \
				-m 1G \
				-kernel $(KERNEL_ELF) \
				-device virtio-blk-pci,drive=x0
else
  	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif


DISASM_TMP := target/$(TARGET)/$(MODE)/asm
FS_IMG := target/fs.img

# temporarily set, need to reset to the situation of competition later
#qemu-system-riscv64 -machine virt -kernel {os_file} -m {mem} -nographic -smp {smp} -bios default -drive file={fs},if=none,format=raw,id=x0 \
#                    -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -no-reboot -device virtio-net-device,netdev=net -netdev user,id=net \
#                    -rtc base=utc \
#                    -drive file=disk.img,if=none,format=raw,id=x1 -device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1
#qemu-system-loongarch64 -kernel {os_file} -m {mem} -nographic -smp {smp} -drive file={fs},if=none,format=raw,id=x0  \
#                        -device virtio-blk-pci,drive=x0,bus=virtio-mmio-bus.0 -no-reboot  -device virtio-net-pci,netdev=net0 \
#                        -netdev user,id=net0,hostfwd=tcp::5555-:5555,hostfwd=udp::5555-:5555  \
#                        -rtc base=utc \
#                        -drive file=disk-la.img,if=none,format=raw,id=x1 -device virtio-blk-pci,drive=x1,bus=virtio-mmio-bus.1
ifeq ($(ARCH),riscv64)
build: env fs-img kernel
else ifeq ($(ARCH),loongarch64)
build:env fs-img kernel
else
	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif


env:
	(rustup target list | grep "$(TARGET) (installed)") || rustup target add $(TARGET)
	cargo install cargo-binutils
	rustup component add rust-src
	rustup component add llvm-tools-preview

$(KERNEL_BIN):
	@$(OBJCOPY) $(KERNEL_ELF) --strip-all -O binary $@

# -s 目录的文件会被载入文件系统镜像内，-t 是文件系统镜像生成的目录
ifeq ($(ARCH),riscv64)
fs-img: $(APPS)	
	@make -C ../user build
	@rm -f $(FS_IMG)
	@cp ../user/build/elf/* ../testcases/riscv64/
	@cp -r $(TESTCASES) ../testcases/riscv64/
	@mkdir -p target
	@cd ../easy-fs-fuse && cargo run --release -- -s ../testcases/riscv64/ -t ../os/target/
else ifeq ($(ARCH),loongarch64)
fs-img: $(APPS)	
	@make build -C ../user_la
	@rm -f $(FS_IMG)
	@cp ../user_la/target/loongarch64-unknown-none/release/initproc ../testcases/loongarch64/
	@cp ../user_la/target/loongarch64-unknown-none/release/user_shell ../testcases/loongarch64/
	@cp ../user_la/target/loongarch64-unknown-none/release/usertests_simple ../testcases/loongarch64/
	@cp -r $(TESTCASES) ../testcases/loongarch64/
	@mkdir -p target
	@cd ../easy-fs-fuse && cargo run --release -- -s ../testcases/loongarch64/ -t ../os/target/	
else
	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif

# cargo build $(MODE_ARG) --target $(TARGET)
kernel:
	@echo Platform: $(BOARD)
	cargo build --$(MODE) -p os --target ${TARGET}

clean:
	@cargo clean
	@tmux kill-server

disasm: kernel
	loongarch64-unknown-linux-gnu-objdump $(DISASM) $(KERNEL_ELF) > disasm_la.s

disasm-vim: kernel
	@$(OBJDUMP) $(DISASM) $(KERNEL_ELF) > $(DISASM_TMP)
	@vim $(DISASM_TMP)
	@rm $(DISASM_TMP)
	
# -d in_asm,cpu,exec,int,unimp,guest_errors
run: build run-inner
QEMU_EXEC += -nographic \
			 -drive file=$(FS_IMG),if=none,format=raw,id=x0 \
			 -smp 1 \
			 -D qemu.log

# @qemu-system-riscv64 \
# 	-M 128m \
# 	-machine virt \
# 	-nographic \
# 	-bios $(BOOTLOADER) \
# 	-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA) \
# 	-drive file=$(FS_IMG),if=none,format=raw,id=x0 \
#     -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0

# qemu-system-loongarch64 \
# 		-m 1G \
# 		-smp 1 \
# 		-kernel $(KERNEL_ELF) \
# 		$(VGA) \
# 		-drive file=$(FS_IMG),if=none,format=raw,id=x0 \
# 		-device ahci,id=ahci0 \
# 		-device ide-hd,drive=x0,bus=ahci0.0


run-inner:
	$(QEMU_EXEC)

# debug, gdbserver and gdbclient no changes
debug: build
	@tmux new-session -d \
		"qemu-system-riscv64 -machine virt -nographic -bios $(BOOTLOADER) -device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA) -drive file=$(FS_IMG),if=none,format=raw,id=x0 -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -s -S" && \
		tmux split-window -h "riscv64-unknown-elf-gdb -ex 'file $(KERNEL_ELF)' -ex 'set arch riscv:rv64' -ex 'target remote localhost:1234'" && \
		tmux -2 attach-session -d


gdbserver: build
	@qemu-system-riscv64 -M 128m -machine virt -nographic -bios $(BOOTLOADER) -device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA) \
	-drive file=$(FS_IMG),if=none,format=raw,id=x0 \
        -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
	-s -S

gdbclient:
	@riscv64-unknown-elf-gdb -ex 'file $(KERNEL_ELF)' -ex 'set arch riscv:rv64' -ex 'target remote localhost:1234'

.PHONY: build env kernel clean disasm disasm-vim run-inner fs-img gdbserver gdbclient
