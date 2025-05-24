# Building
ARCH := riscv64
MODE := release

# BOARD
BOARD := qemu
SBI ?= rustsbi
BOOTLOADER := ../bootloader/$(SBI)-$(BOARD).bin

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
DISASM ?= -x

# Tesecases
TESTSUITS := $(wildcard ../testsuits/*)
TESTCASES := $(filter-out %.sh %.txt %/mnt, $(TESTSUITS))

ifeq ($(ARCH), riscv64)
  	TARGET := riscv64gc-unknown-none-elf
	KERNEL_ELF := target/$(TARGET)/$(MODE)/os
	KERNEL_BIN := $(KERNEL_ELF).bin
	QEMU_EXEC += qemu-system-$(ARCH) \
				-M 128m \
				-machine virt \
				-bios $(BOOTLOADER) \
				-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
				-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA)
else ifeq ($(ARCH), loongarch64)
  	TARGET := loongarch64-unknown-none
	KERNEL_ELF := target/$(TARGET)/$(MODE)/os
  	QEMU_EXEC += qemu-system-$(ARCH) \
				-m 1G \
				-device ahci,id=ahci0 \
				-device ide-hd,drive=x0,bus=ahci0.0 \
				-kernel $(KERNEL_ELF)
				
else
  	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif


DISASM_TMP := target/$(TARGET)/$(MODE)/asm
FS_IMG := target/fs.img
APPS := ../user/src/bin/*

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

build: env fs-img kernel $(KERNEL_BIN)

env:
	(rustup target list | grep "$(TARGET) (installed)") || rustup target add $(TARGET)
	cargo install cargo-binutils
	rustup component add rust-src
	rustup component add llvm-tools-preview

$(KERNEL_BIN) kernel:
	@$(OBJCOPY) $(KERNEL_ELF) --strip-all -O binary $@

#@make -C ../user build
#@make -C ../testcases build
fs-img: $(APPS)	
	@make -C ../user build
	@make -C ../testcases build
	@rm -f $(FS_IMG)
	@cp ../user/build/elf/* ../testcases/build/
	@cp -r $(TESTCASES) ../testcases/build/
	@mkdir -p target
	@cd ../easy-fs-fuse && cargo run --release -- -s ../testcases/build/ -t ../os/target/

$(APPS):

kernel:
	@echo Platform: $(BOARD)
	cargo build $(MODE_ARG) --target $(TARGET)

clean:
	@cargo clean
	@tmux kill-server

disasm: kernel
	@$(OBJDUMP) $(DISASM) $(KERNEL_ELF) | less

disasm-vim: kernel
	@$(OBJDUMP) $(DISASM) $(KERNEL_ELF) > $(DISASM_TMP)
	@vim $(DISASM_TMP)
	@rm $(DISASM_TMP)

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
