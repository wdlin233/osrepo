# Building, riscv64 or loongarch64
ARCH := riscv64
MODE := release

# Binutils, objcopy riscv64 only
OBJCOPY := rust-objcopy --binary-architecture=riscv64

# Disassembly
DISASM ?= -d

# QEMU execution
ifeq ($(ARCH), riscv64)
  	TARGET := riscv64gc-unknown-none-elf
	KERNEL_ELF := target/$(TARGET)/$(MODE)/os
	KERNEL_BIN := $(KERNEL_ELF).bin
	QEMU_EXEC += qemu-system-$(ARCH) \
				-M 128m \
				-machine virt \
				-kernel $(KERNEL_ELF) \
				-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0
	FS_IMG := sdcard-rv.img
else ifeq ($(ARCH), loongarch64)
  	TARGET := loongarch64-unknown-none
	KERNEL_ELF := target/$(TARGET)/$(MODE)/os
  	QEMU_EXEC += qemu-system-$(ARCH) \
				-m 1G \
				-kernel $(KERNEL_ELF) \
				-device virtio-blk-pci,drive=x0
	FS_IMG := sdcard-la.img
else
  	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif

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
build: env config kernel

$(KERNEL_BIN): kernel
	@echo "Building kernel binary..."
	@$(OBJCOPY) $(KERNEL_ELF) --strip-all -O binary $@
else ifeq ($(ARCH),loongarch64)
build: env config kernel
else
	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif


env:
	(rustup target list | grep "$(TARGET) (installed)") || rustup target add $(TARGET)
	cargo install cargo-binutils
	rustup component add rust-src
	rustup component add llvm-tools-preview

# cargo build $(MODE_ARG) --target $(TARGET)
kernel:
	cargo build --$(MODE) -p os --target ${TARGET} --offline

config:
	@rm -rf .cargo
	@cp -r cargo .cargo

clean:
	@cargo clean
	-tmux kill-server
	@sudo umount /mnt/image_part

# Debugging
ifeq ($(ARCH),riscv64)
modify:
	@cp ${HOME}/sdcard-rv.img  ${HOME}/osrepo/os/sdcard-rv.img
disasm: kernel
	rust-objdump --arch-name=riscv64 $(DISASM) $(KERNEL_ELF) > disasm_rv.s
else ifeq ($(ARCH),loongarch64)
modify:
	@cp ${HOME}/sdcard-la.img  ${HOME}/osrepo/os/sdcard-la.img
disasm: kernel	
	loongarch64-unknown-linux-gnu-objdump $(DISASM) $(KERNEL_ELF) > disasm_la.s
else
	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif

# -d in_asm,cpu,exec,int,unimp,guest_errors
run: build run-inner
QEMU_EXEC += -nographic \
			 -drive file=$(FS_IMG),if=none,format=raw,id=x0 \
			 -smp 1 \
			 -D qemu.log \
# -monitor telnet:127.0.0.1:5555,server,nowait

run-inner:
	$(QEMU_EXEC)

.PHONY: build env kernel clean disasm disasm-vim run-inner fs-img gdbserver gdbclient config modfiy gdb gdb-connect gdb-auto