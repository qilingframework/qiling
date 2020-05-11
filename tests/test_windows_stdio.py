#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
from unicorn import *

from unicorn.x86_const import *

import sys
sys.path.append("..")
from qiling import *

class StringBuffer:
    def __init__(self):
        self.buffer = b''

    def read(self, n):
        ret = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return ret

    def read_all(self):
        ret = self.buffer
        self.buffer = b''
        return ret

    def write(self, string):
        self.buffer += string
        return len(string)


def instruction_count(ql, address, size, user_data):
    user_data[0] += 1


def get_count(flag):
    ql = Qiling(["../examples/rootfs/x86_windows/bin/crackme.exe"], "../examples/rootfs/x86_windows", output="off", libcache = True)
    ql.stdin = StringBuffer()
    ql.stdout = StringBuffer()
    ql.stdin.write(bytes("".join(flag) + "\n", 'utf-8'))
    count = [0]
    ql.hook_code(instruction_count, count)
    ql.run()
    print(ql.stdout.read_all().decode('utf-8'), end='')
    print(" ============ count: %d ============ " % count[0])
    return count[0]


def solve():
    # BJWXB_CTF{C5307D46-E70E-4038-B6F9-8C3F698B7C53}
    prefix = list("BJWXB_CTF{C5307D46-E70E-4038-B6F9-8C3F698B7C")
    flag = list("\x00" * 100)
    base = get_count(prefix + flag)
    i = 0

    try:
        for i in range(len(flag)):
            for j in "}5353535353":
                flag[i] = j
                data = get_count(prefix + flag)
                if data > base:
                    base = data
                    print("\n\n\n>>> FLAG: " + "".join(prefix + flag) + "\n\n\n")
                    break
            if flag[i] == "}":
                break
        print("SOLVED!!!")
    except KeyboardInterrupt:
        print("STOP: KeyboardInterrupt")


if __name__ == "__main__":
    solve()
