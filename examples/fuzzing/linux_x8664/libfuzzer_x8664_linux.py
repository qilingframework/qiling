#!/usr/bin/python3

from fuzzercorn import *
from unicorn import *
from qiling import Qiling
from qiling.extensions import pipe

import sys, os, ctypes

class SimpleFuzzer:

    def run(self):
        ql = Qiling(["./x8664_fuzz"], "../../rootfs/x8664_linux", console=False)
        ba = ql.loader.images[0].base
        try:
            # Only instrument the function `fun`, so we don't need to instrument libc and ld
            FuzzerCornFuzz(ql.uc, sys.argv, [ql.os.exit_point], self.place_input, self.init, UserData=ql, Ranges=[(ba + 0x1179, ba + 0x122B)], CountersCount=4096)
        except Exception as ex:
            os.abort() # Quick exit
    
    def place_input(self, uc: Uc, data: ctypes.Array, ql: Qiling):
        ql.restore(self.snapshot)
        ql.os.stdin = pipe.SimpleInStream(1)
        ql.os.stdin.write(bytes(data))
        return 1

    def init(self, uc: Uc, argv: list, ql: Qiling):
        ba = ql.loader.images[0].base
        ql.hook_address(callback=lambda x: os.abort(), address=ba + 0x1225) # ___stack_chk_fail
        ql.run(end=ba + 0x122c) # Run to main.

        # Save a snapshot.
        self.snapshot = ql.save()
        return 0
    

if __name__ == "__main__":
    # chmod +x ./libfuzzer_x8664_linux.py
    # ./libfuzzer_x8664_linux.py -jobs=6 -workers=6
    SimpleFuzzer().run()

