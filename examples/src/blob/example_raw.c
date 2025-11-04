// example checksum algorithm to demonstrate raw binary code coverage in qiling
// example_raw.c

// Define some magic values
#define MAGIC_VALUE_1 0xDE
#define MAGIC_VALUE_2 0xAD

// This function calculates a checksum with branches based on input data
// It takes a pointer to data and its length
// Returns the checksum (unsigned char to fit in a byte)
unsigned char calculate_checksum(const unsigned char *data, unsigned int length) {
    unsigned char checksum = 0;

    // Branch 1: Check for MAGIC_VALUE_1 at the start
    if (length >= 1 && data[0] == MAGIC_VALUE_1) {
        // If first byte is MAGIC_VALUE_1, do a simple sum of first 4 bytes
        // (or up to length if less than 4)
        for (unsigned int i = 0; i < length && i < 4; i++) {
            checksum += data[i];
        }
        // Add a fixed offset to make this path distinct
        checksum += 0x10;
    }
    // Branch 2: Check for MAGIC_VALUE_2 at the second byte
    else if (length >= 2 && data[1] == MAGIC_VALUE_2) {
        // If second byte is MAGIC_VALUE_2, do a XOR sum of all bytes
        for (unsigned int i = 0; i < length; i++) {
            checksum ^= data[i];
        }
        // Add a fixed offset to make this path distinct
        checksum += 0x20;
    }
    // Default Branch: Standard byte sum checksum
    else {
        for (unsigned int i = 0; i < length; i++) {
            checksum += data[i];
        }
    }

    return checksum;
}

// Minimal entry point for bare-metal.
// This function will not be called directly during Qiling emulation,
// but it's needed for the linker to have an entry point.
__attribute__((section(".text.startup")))
void _start() {
    // In a real bare-metal application, this would initialize hardware,
    // set up stacks, etc. For this example, it's just a placeholder.
    // We'll call calculate_checksum directly from our Qiling script.

    while (1) {
        // Do nothing, or perhaps put the CPU to sleep
        asm volatile ("wfi"); // Wait For Interrupt (ARM instruction)
    }
}