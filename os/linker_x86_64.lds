OUTPUT_ARCH(x86_64)
ENTRY(_start)

BASE_ADDRESS = 0;

SECTIONS
{
    . = BASE_ADDRESS;
    _skernel = .;

    .text ALIGN(4K): {
        *(.multiboot .multiboot.*)
        stext = .;
        *(.text.entry)
        *(.text .text.*)
        etext = .;
    }

    .rodata ALIGN(4K): {
        srodata = .;
        *(.rodata .rodata.*)
        erodata = .;
    }

    .got : {
        *(.got .got.*)
    }

    .data ALIGN(4K): {
        _sdata = .;
        . = ALIGN(4K);
        *(.data.boot_page_table)

        *(.data .data.*)
        *(.sdata .sdata.*)
        _edata = .;
    }

    .bss ALIGN(4K): {
        _load_end = .;
        *(.bss.bstack .bss.bstack.*)
        _sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        _ebss = .;
    }

    PROVIDE(_end = .);
    /DISCARD/ : {
        *(.comment) *(.gnu*) *(.note*) *(.eh_frame*) *(.debug*)
    }
}