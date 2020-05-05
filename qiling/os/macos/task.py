#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

# task class not finished 
# TODO: finished
class MachoTask():
    def __init__(self):
        self.id = 9876                  # random id
        self.min_offset = 0x00000000
        self.max_offset = 0xFFE00000