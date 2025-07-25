TARGET := loongarch64-unknown-none
MODE := release
APP_DIR := src/bin
TARGET_DIR := target/$(TARGET)/$(MODE)

OBJCOPY := loongarch64-unknown-linux-gnu-objcopy

all: build

build: config
	cargo build --release --target $(TARGET)

config:
	rustup target add $(TARGET)

clean:
	@cargo clean

.PHONY: clean build all config

