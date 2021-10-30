#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


def byte2bcd(value):
    bcdhigh = 0
    while value >= 10:
        bcdhigh += 1
        value -= 10

    return (bcdhigh << 4) | value