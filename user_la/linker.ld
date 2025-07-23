OUTPUT_ARCH( "loongarch" )
ENTRY( _start)


SECTIONS
{
  . = 0x10000;
  . = ALIGN(4K);
  .text : {
    *(.text.entry)
    *(.text .text.*)
    PROVIDE(etext = .);
  }
  . = ALIGN(4K);
  .rodata ALIGN(4K): {
    *(.rodata .rodata.*)
    *(.srodata .srodata.*)
  }
  . = ALIGN(4K);
  .data ALIGN(4K): {
    *(.data .data.*)
    *(.sdata .sdata.*)
  }
  . = ALIGN(4K);
  .bss ALIGN(4K): {
    sbss = .;
    *(.bss .bss.*)
    *(.sbss .sbss.*)
    ebss = .;
  }
  PROVIDE(end = .);
}