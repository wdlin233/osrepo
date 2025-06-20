ARCH ?= riscv64
DOCKER_NAME ?= docker.educg.net/cg/os-contest:20250516
.PHONY: docker build_docker all
	
docker:
	docker run -it -v .:/code --entrypoint bash -w /code --privileged ${DOCKER_NAME}

build_docker: 
	docker build -t ${DOCKER_NAME} .

all: clean
	@cd os && make run ARCH=$(ARCH)

clean:
	@cd ./os && make clean
	@cd ./user && make clean
	@cd ./user_la && make clean

