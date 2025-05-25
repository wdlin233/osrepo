ARCH := loongarch64

ifeq ($(ARCH), riscv64)
  	TARGET := riscv64gc-unknown-none-elf
else ifeq ($(ARCH), loongarch64)
  	TARGET := loongarch64-unknown-none
else
  	$(error "ARCH" must be one of "riscv64" or "loongarch64")
endif

MODE := release
APP_DIR := src/bin
TARGET_DIR := target/$(TARGET)/$(MODE)
BUILD_DIR := build
OBJDUMP := rust-objdump --arch-name=riscv64
#OBJCOPY := rust-objcopy --binary-architecture=riscv64
OBJCOPY := loongarch64-unknown-linux-gnu-objcopy
PY := python3

ifeq ($(MODE), release)
	MODE_ARG := --release
endif

APPS := $(wildcard $(APP_DIR)/*.rs)
ELFS := $(patsubst $(APP_DIR)/%.rs, $(TARGET_DIR)/%, $(APPS))

binary:
	@echo $(ELFS)
	cargo build $(MODE_ARG)
	@$(foreach elf, $(ELFS), \
		$(OBJCOPY) $(elf) --strip-all -O binary $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.bin, $(elf)); \
		cp $(elf) $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.elf, $(elf));)

disasm:
	@$(foreach elf, $(ELFS), \
		$(OBJDUMP) $(elf) -S > $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.asm, $(elf));)
	@$(foreach t, $(ELFS), cp $(t).asm $(BUILD_DIR)/asm/;)

pre:
	@mkdir -p $(BUILD_DIR)/bin/
	@mkdir -p $(BUILD_DIR)/elf/
	@mkdir -p $(BUILD_DIR)/app/
	@mkdir -p $(BUILD_DIR)/asm/
	@$(foreach t, $(APPS), cp $(t) $(BUILD_DIR)/app/;)

ifeq ($(ARCH),riscv64)
build: clean pre binary
	@$(foreach t, $(ELFS), cp $(t).bin $(BUILD_DIR)/bin/;)
	@$(foreach t, $(ELFS), cp $(t).elf $(BUILD_DIR)/elf/;)
else ifeq ($(ARCH),loongarch64)
build:
	@cargo build --release --target $(TARGET)
endif

clean:
	@cargo clean
	@rm -rf $(BUILD_DIR)

all: build

.PHONY: elf binary build clean all