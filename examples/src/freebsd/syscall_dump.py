#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

# https://github.com/freebsd/freebsd/blob/master/sys/kern/syscalls.master

import re

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass

    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass

    return False

def read_file(f):
    line = f.readline()
    while line:
        if is_number(line[0]):
            index = re.findall(r"\d+\.?\d*", line)
            line = f.readline()
            if not is_number(line[0]) and line[0] != ';':
                name = line.split('(')[0]
                name = name.split(' ')[-1]
                # print(index[0], name)
                if name != '\n':
                    print("    \""+name+"\": ("+index[0]+"),")
            else:
                continue
        line = f.readline()

if __name__ == '__main__':
    file = open('./syscalls.master')
    read_file(file)
