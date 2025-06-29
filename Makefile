ARCH ?= riscv64
DOCKER_NAME ?= docker.educg.net/cg/os-contest:20250516
.PHONY: docker build_docker all
	
docker:
	docker run -it -v .:/code --entrypoint bash -w /code --privileged ${DOCKER_NAME}

build_docker: 
	docker build -t ${DOCKER_NAME} .

all:
	@cd user && make build ARCH=riscv64
	@cd os && make build ARCH=riscv64
	@cd user_la && make build ARCH=loongarch64
	@cd os && make build ARCH=loongarch64
	@cp ./os/target/riscv64gc-unknown-none-elf/release/os ./kernel-rv
	@cp ./os/target/loongarch64-unknown-none/release/os ./kernel-la

clean:
	@cd ./os && make clean
	@cd ./user && make clean
	@cd ./user_la && make clean

