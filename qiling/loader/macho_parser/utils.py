#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

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


def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % x for x in chars])
        printable = ''.join(["%s" % ((x <= 127 and FILTER[x]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)
