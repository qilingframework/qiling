#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
from qiling.os.posix.stat import Fstat
import sys
sys.path.append("..")

import os
from qiling import Qiling

class MyPipe():
    def __init__(self):
        self.buf = b''

    def write(self, s):
        self.buf += s

    def read(self, l):
        if l <= len(self.buf):
            ret = self.buf[ : l]
            self.buf = self.buf[l : ]
        else:
            ret = self.buf
            self.buf = ''
        return ret

    def fileno(self):
        return 0

    def fstat(self):
        return Fstat(sys.stdin.fileno())

    def show(self):
        pass

    def clear(self):
        pass

    def flush(self):
        pass

    def close(self):
        self.outpipe.close()


def instruction_count(ql, address, size, user_data):
    user_data[0] += 1

def my__llseek(ql, *args, **kw):
    pass

def run_one_round(payload):
    stdin = MyPipe()
    ql = Qiling(["../examples/rootfs/x86_linux/bin/crackme_linux"], "../examples/rootfs/x86_linux", console = False, stdin = stdin)
    ins_count = [0]
    ql.hook_code(instruction_count, ins_count)
    ql.set_syscall("_llseek", my__llseek)
    stdin.write(payload)
    ql.run()
    del stdin
    return ins_count[0]


def solve():
    idx_list = [1, 4, 2, 0, 3]

    flag = b'\x00\x00\x00\x00\x00\n'

    old_count = run_one_round(flag)
    for idx in idx_list:
        for i in b'123LNMNUX\\n':#'L1NUX\\n'
            flag = flag[ : idx] + chr(i).encode() + flag[idx + 1 : ]
            tmp = run_one_round(flag)
            if tmp > old_count:
                old_count = tmp
                break
        # if idx == 2:
        #     break

    print(flag)
if __name__ == "__main__":
    solve()
