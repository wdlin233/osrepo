OUTPUT_ARCH( "loongarch" )
ENTRY( _start)

SECTIONS
{

  . = 0x9000000000200000;
  
  .text : {
    PROVIDE(stext = .);
    *(.text.init)
    *(.text .text.*)
    . = ALIGN(0x1000);
    *(tlb_handler)
    PROVIDE(etext = .);
  }
  . = ALIGN(1K);


  .rodata : {
    PROVIDE(srodata = .);
    . = ALIGN(4);
    *(.srodata .srodata.*)
    . = ALIGN(4);
    *(.rodata .rodata.*)
    PROVIDE(erodata = .);
  }
  . = ALIGN(1K);

  .data : {
    PROVIDE(sdata = .);
    . = ALIGN(4);
    *(.sdata .sdata.*)
    . = ALIGN(4);
    *(.data .data.*)
    *(.got .got.*)
  }
  . = ALIGN(1K);
  PROVIDE(edata = .);

  .bss : {
    *(.bss.stack)
    sbss = .;
    *(.sbss .sbss.*)
    *(.bss .bss.*)
    ebss = .;
  }
  . = ALIGN(1K);


  ekernel = .;
  /DISCARD/ : {
      *(.eh_frame)
  }
}