# Makefile

docker:
	docker run -it -v .:/code --entrypoint bash -w /code --privileged docker.educg.net/cg/os-contest:20250516

build_docker: 
	docker build -t ${DOCKER_NAME} .

fmt:
	cd easy-fs; cargo fmt; cd ../easy-fs-fuse cargo fmt; cd ../os ; cargo fmt; cd ../user; cargo fmt; cd ..

.PHONY: all docker build_docker