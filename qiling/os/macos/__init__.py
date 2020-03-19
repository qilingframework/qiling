#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

# virtual addr :  0x00000000000 -  0x7FFFFFFFFFF
    # 64 bit case no aslr:
        # 0x000000000 - 0x100000000  page zero
        # 0x100000000 - 0xXXXXXXXXX  binary
        # 0xXXXXXXXXX - 0xYYYYYYYYY  dyld
        # 0x7ffcf0000000 - 0x7ffd09a00000  stack 
        # 0x7ffbf0100000 - 0x7ffcf0000000  heap
        # 0x7FFF00000000 - 0x7fffffe00000  shared origen
# kernel space :  0x80000000000 -  0xFFFFFFFFFFF
# other space  :  0x100000000000 - 0x17FFFFFFFFFF