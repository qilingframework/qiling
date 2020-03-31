#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

class FileReader:

    def __init__(self, binary):
        self.binary = binary
        self.offset = 0

    def read(self, size):
        data = self.binary[self.offset : self.offset + size]
        self.offset += size
        #print(data)
        return data

    def setOffset(self, offset):
        self.offset = offset

    def readString(self, align):
        str_size = 0
        while True:
            if self.binary[self.offset + str_size] != 0:
                str_size += 1
            else:
                str_size += 1
                break

        result = self.binary[self.offset : self.offset + str_size].decode("utf-8")

        if str_size % align != 0:
            self.offset += ((str_size // align) + 1) * align
        else:
            self.offset += str_size

        return result.strip(b'\x00'.decode())
        