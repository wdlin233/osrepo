# Building, riscv64 or loongarch64
ARCH := riscv64
MODE := release

# Building mode argument
ifeq ($(MODE), release)
	MODE_ARG := --release
endif

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


ifeq ($(ARCH), riscv64)
	FS_IMG := sdcard-rv.img
else ifeq ($(ARCH), loongarch64)
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
build: env fs-img kernel config
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
#		
ifeq ($(ARCH),riscv64)
fs-img:
	@sudo mkdir -p /mnt/image_part
	@make -C ../user build
	@sudo mount $(FS_IMG) /mnt/image_part
	@sudo cp ../user/build/elf/* /mnt/image_part/
	@sudo cp -r $(TESTSUITS) /mnt/image_part/
	-sudo cp ../testcases/riscv64/busybox /mnt/image_part/
	@sudo ls /mnt/image_part/
	@sudo umount /mnt/image_part
else ifeq ($(ARCH),loongarch64)
fs-img:
	@sudo mkdir -p /mnt/image_part
	@sudo mount $(FS_IMG) /mnt/image_part
	@make build -C ../user_la
	@sudo cp ../user_la/target/loongarch64-unknown-none/release/initproc /mnt/image_part/
	@sudo cp ../user_la/target/loongarch64-unknown-none/release/user_shell /mnt/image_part/
	@sudo cp ../user_la/target/loongarch64-unknown-none/release/usertest /mnt/image_part/
	@sudo cp -r $(TESTSUITS) /mnt/image_part/
	@sudo cp ../testcases/riscv64/busybox /mnt/image_part/
	@sudo cp ../test-riscv/musl/* /mnt/image_part/
	@sudo ls /mnt/image_part/
	@sudo umount /mnt/image_part
else
	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif

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

ifeq ($(ARCH),riscv64)
modify:
	@cp ${HOME}/sdcard-rv.img  ${HOME}/osrepo/os/sdcard-rv.img
else ifeq ($(ARCH),loongarch64)
modify:
	@cp ${HOME}/sdcard-la.img  ${HOME}/osrepo/os/sdcard-la.img
else
	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif

ifeq ($(ARCH),riscv64)
disasm: kernel
	rust-objdump --arch-name=riscv64 $(DISASM) $(KERNEL_ELF) > disasm_rv.s
else ifeq ($(ARCH),loongarch64)
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
			 -monitor telnet:127.0.0.1:5555,server,nowait

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



# ====== GDB 调试配置 ======
GDB_PORT := 1234
GDB := gdb-multiarch

# 通用调试目标
gdb: build
	@echo "启动 QEMU GDB 服务器..."
	$(QEMU_EXEC) -s -S

gdb-connect:
ifeq ($(ARCH), riscv64)
	@echo "连接 RISC-V GDB..."
	$(GDB) -ex "target remote :1234" \
	       -ex "file $(KERNEL_ELF)" \
	       -ex "set arch riscv:rv64"  # 注意这里是 riscv:rv64
else ifeq ($(ARCH), loongarch64)
	@echo "连接 LoongArch GDB..."
	$(GDB) -ex "target remote :$(GDB_PORT)" -ex "file $(KERNEL_ELF)" -ex "set arch loongarch64"
endif

# 自动调试 (需要 tmux)
gdb-auto: build
	@tmux new-session -d \
		"$(QEMU_EXEC) -s -S" && \
	tmux split-window -h \
		"$(GDB) -ex 'target remote :$(GDB_PORT)' -ex 'file $(KERNEL_ELF)' -ex 'set arch $(ARCH)' -ex 'b rust_main'" && \
	tmux -2 attach-session -d

.PHONY: build env kernel clean disasm disasm-vim run-inner fs-img gdbserver gdbclient config modfiy gdb gdb-connect gdb-auto