#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import os

from unicorn import *

import sys
sys.path.append("..")
from qiling import *



class MyPipe():
    def __init__(self):
        self.buf = b''

    def write(self, s):
        self.buf += s

    def read(self, size):
        if size <= len(self.buf):
            ret = self.buf[: size]
            self.buf = self.buf[size:]
        else:
            ret = self.buf
            self.buf = ''
        return ret

    def fileno(self):
        return 0

    def show(self):
        pass

    def clear(self):
        pass

    def flush(self):
        pass

    def close(self):
        self.outpipe.close()

    def fstat(self):
        return os.fstat(sys.stdin.fileno())


def instruction_count(ql, address, size, user_data):
    user_data[0] += 1


def run_one_round(payload):
    stdin = MyPipe()
    ql = Qiling(["rootfs/x86_linux/bin/crackme_linux"], "rootfs/x86_linux", console=False, stdin=stdin,
                stdout=sys.stdout, stderr=sys.stderr)
    ins_count = [0]
    ql.hook_code(instruction_count, ins_count)
    stdin.write(payload)
    ql.run()
    del stdin
    del ql
    return ins_count[0]


def solve():
    idx_list = [1, 4, 2, 0, 3]

    flag = b'\x00\x00\x00\x00\x00\n'

    old_count = run_one_round(flag)
    for idx in idx_list:
        for i in b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
            flag = flag[: idx] + chr(i).encode() + flag[idx + 1:]
            tmp = run_one_round(flag)
            if tmp > old_count:
                old_count = tmp
                break
        # if idx == 2:
        #     break

    print(flag)


if __name__ == "__main__":
    solve()
