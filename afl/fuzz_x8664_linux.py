#!/usr/bin/env python3
"""
Simple example of how to use Qiling together with AFLplusplus.
This is tested with the recent Qiling framework (the one you cloned),
afl++ from https://github.com/AFLplusplus/AFLplusplus

After building afl++, make sure you install `unicorn_mode/setup_unicorn.sh`

Then, run this file using afl++ unicorn mode with
afl-fuzz -i ./afl_inputs -o ./afl_outputs -m none -U -- python3 ./fuzz_x8664_linux.py @@
"""

# This is new. Instead of unicorn, we import unicornafl. It's the same Uc with some new `afl_` functions
import unicornafl

# Make sure Qiling uses our patched unicorn instead of it's own, second so without instrumentation!
unicornafl.monkeypatch()

import sys

sys.path.append("..")
from qiling import *


class MyPipe:
    """
    Copied straight off the tutorials (crackme_x64_linux.py)
    """

    def __init__(self):
        self.buf = b''

    def write(self, s):
        self.buf += s

    def read(self, l):
        if l <= len(self.buf):
            ret = self.buf[: l]
            self.buf = self.buf[l:]
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


X64BASE = 0x555555554000


# 64 bit loader addrs are placed at 0x555555554000
# see loader/elf.py:load_with_ld(..)


def main(inputfile):
    stdin = MyPipe()
    ql = Qiling(["./x8664_fuzz"], "../examples/rootfs/x8664_linux", stdin=stdin,
                stdout=None, stderr=None, output="off")

    # or this for output:
    # ... stdout=sys.stdout, stderr=sys.stderr)

    def start_afl(_ql: Qiling):
        """
        Callback from inside
        """
        print("At main :) - Starting forkserver if AFL is available.")
        # We start our AFL forkserver (if AFL is available)
        status = ql.uc.afl_forkserver_start(exits=[ql.until_addr])
        if status == unicornafl.UC_AFL_RET_FINISHED:
            print("Done fuzzing. Cya :)")
            exit(0)
        # we're either a fuzzing child or running without AFL at this point.
        with open(inputfile, "rb") as f:
            stdin.write(f.read())

    # Add hook at main() that will fork Unicorn and start instrumentation.
    # main starts at X64BASE + 0x122c
    main_addr = X64BASE + 0x122c
    ql.hook_address(callback=start_afl, address=main_addr)

    # crash in case we reach stackcheck_fail:
    # 1225:	e8 16 fe ff ff       	callq  1040 <__stack_chk_fail@plt>
    ql.hook_address(callback=lambda x: os.abort(), address=X64BASE + 0x1225)

    # okay, ready to roll.
    try:
        ql.run()
    except Exception as ex:
        # Probable unicorn memory error. Treat as crash.
        print(ex)
        os.abort()

    os._exit(0)  # that's a looot faster than tidying up.


if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise ValueError("No input file provided.")
    main(sys.argv[1])
