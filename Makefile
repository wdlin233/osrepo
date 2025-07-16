ARCH ?= riscv64
DOCKER_NAME ?= docker.educg.net/cg/os-contest:20250516
ifeq ($(ARCH), riscv64)
	KERNEL := kernel-rv
	FS_IMG := sdcard-rv.img
else ifeq ($(ARCH), loongarch64)
	KERNEL := kernel-la
	FS_IMG := sdcard-la.img
else
  	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif

.PHONY: docker build_docker all



docker:
	docker run -it -v .:/code --entrypoint bash -w /code --privileged ${DOCKER_NAME}

build_docker: 
	docker build -t ${DOCKER_NAME} .

all:
	@cd user && make build ARCH=riscv64
	@cd os && make build ARCH=riscv64
	@cp ./os/target/riscv64gc-unknown-none-elf/release/os ./kernel-rv

clean:
	@cd ./os && make clean
	@cd ./user && make clean
	@cd ./user_la && make clean

ifeq ($(ARCH), riscv64)
run: all
	qemu-system-riscv64 -machine virt -kernel $(KERNEL) -m 1G -nographic -smp 1 -bios default -drive file=$(FS_IMG),if=none,format=raw,id=x0 \
                   -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -no-reboot

else ifeq ($(ARCH), loongarch64)
run: all
	qemu-system-loongarch64 -kernel $(KERNEL) -m 1G -nographic -smp 1 -drive file=$(FS_IMG),if=none,format=raw,id=x0  \
					-device virtio-blk-pci,drive=x0,bus=virtio-mmio-bus.0 -no-reboot  -device virtio-net-pci,netdev=net0 \
					id=net0,hostfwd=tcp::5555-:5555,hostfwd=udp::5555-:5555  \
					-drive file=disk-la.img,if=none,format=raw,id=x1 -device virtio-blk-pci,drive=x1,bus=virtio-mmio-bus.1
else
  	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif

modify:
	@cp ${HOME}/sdcard-rv.img  ${HOME}/osrepo/sdcard-rv.img