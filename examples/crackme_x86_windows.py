#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import pipe

def instruction_count(ql: Qiling, address: int, size: int, user_data):
    user_data[0] += 1

def get_count(flag):
    mock_stdin = pipe.SimpleStringBuffer()
    mock_stdout = pipe.SimpleStringBuffer()

    ql = Qiling(["rootfs/x86_windows/bin/crackme.exe"], "rootfs/x86_windows",
        verbose=QL_VERBOSE.OFF,
        stdin=mock_stdin,
        stdout=mock_stdout)

    ql.os.stdin.write(bytes("".join(flag) + "\n", 'utf-8'))
    count = [0]

    ql.hook_code(instruction_count, count)
    ql.run()

    print(ql.os.stdout.read().decode('utf-8'), end='')
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
            for j in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-{}":
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
