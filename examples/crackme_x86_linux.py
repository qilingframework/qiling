#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

import os
from qiling import Qiling

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

def instruction_count(ql: Qiling, address: int, size: int, user_data):
    user_data[0] += 1

def my__llseek(ql, *args, **kw):
    pass

def run_one_round(payload: bytes):
    stdin = MyPipe()

    ql = Qiling(["rootfs/x86_linux/bin/crackme_linux"], "rootfs/x86_linux",
        console=False,      # thwart qiling logger output
        stdin=stdin,        # take over the input to the program
        stdout=sys.stdout)  # thwart program output

    ins_count = [0]
    ql.hook_code(instruction_count, ins_count)
    ql.set_syscall("_llseek", my__llseek)

    stdin.write(payload + b'\n')
    ql.run()

    del stdin
    del ql

    return ins_count[0]

def solve():
    idx_list = (1, 4, 2, 0, 3)
    flag = [0] * len(idx_list)

    prev_ic = run_one_round(bytes(flag))
    for idx in idx_list:

        # bruteforce all possible flag characters
        for ch in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ':
            flag[idx] = ord(ch)

            print(f'\rguessing char at {idx}: {ch}... ', end='', flush=True)
            ic = run_one_round(bytes(flag))

            if ic > prev_ic:
                print(f'ok')
                prev_ic = ic
                break
        else:
            print(f'no match found')

    print(f'flag: "{"".join(chr(ch) for ch in flag)}"')

if __name__ == "__main__":
    solve()
