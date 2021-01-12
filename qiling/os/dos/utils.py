#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

def BIN2BCD(val: int):
    return val % 10 + (((val//10) % 10) << 4) + (((val//100) % 10) << 8) + (((val//1000) % 10) << 12)


def BCD2BIN(val: int):
    return (val & 0xF) + ((val >> 4) & 0xF) * 10 + ((val >> 8) & 0xF) * 100 + ((val >> 12) & 0xF) * 1000
