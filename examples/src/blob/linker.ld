/* linker.ld */

ENTRY(_start) /* Define the entry point of our program */

/* Define memory regions - simple RAM region for this example */
MEMORY
{
    ram (rwx) : ORIGIN = 0x10000000, LENGTH = 64K /* 64KB of RAM for our program */
}

SECTIONS
{
    /* Define the start of our program in memory.
     */
    . = 0x10000000;

    .text : {
        KEEP(*(.text.startup)) /* Keep the _start function */
        *(.text)             /* All other code */
        *(.text.*)
        *(.rodata)           /* Read-only data */
        *(.rodata.*)
        . = ALIGN(4);
    } > ram /* Place .text section in the 'ram' region */

    .data : {
        . = ALIGN(4);
        *(.data)             /* Initialized data */
        *(.data.*)
        . = ALIGN(4);
    } > ram

    .bss : {
        . = ALIGN(4);
        *(.bss)
        *(.bss.*)
        . = ALIGN(4);
    } > ram
}