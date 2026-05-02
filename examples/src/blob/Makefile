# Makefile for Bare-Metal ARM Checksum Calculator

# --- Toolchain Definitions ---
TOOLCHAIN_PREFIX = arm-none-eabi

# Compiler, Linker, and Objcopy executables
CC = $(TOOLCHAIN_PREFIX)-gcc
LD = $(TOOLCHAIN_PREFIX)-gcc
OBJCOPY = $(TOOLCHAIN_PREFIX)-objcopy

# --- Source and Output Files ---
SRCS = example_raw.c
OBJS = $(SRCS:.c=.o) # Convert .c to .o
ELF = example_raw.elf
BIN = example_raw.bin

# --- Linker Script ---
LDSCRIPT = linker.ld

# --- Compiler Flags ---
CFLAGS = -c -O0 -mcpu=cortex-a7 -mthumb -ffreestanding -nostdlib

# --- Linker Flags ---
LDFLAGS = -T $(LDSCRIPT) -nostdlib

# --- Objcopy Flags ---
OBJCOPYFLAGS = -O binary

# --- Default Target ---
.PHONY: all clean

all: $(BIN)

# Rule to build the raw binary (.bin) from the ELF file
$(BIN): $(ELF)
	$(OBJCOPY) $(OBJCOPYFLAGS) $< $@
	@echo "Successfully created $(BIN)"

# Rule to link the object file into an ELF executable
$(ELF): $(OBJS) $(LDSCRIPT)
	$(LD) $(LDFLAGS) $(OBJS) -o $@
	@echo "Successfully linked $(ELF)"

# Rule to compile the C source file into an object file
%.o: %.c
	$(CC) $(CFLAGS) $< -o $@
	@echo "Successfully compiled $<"

# --- Clean Rule ---
clean:
	rm -f $(OBJS) $(ELF) $(BIN)
	@echo "Cleaned build artifacts."
