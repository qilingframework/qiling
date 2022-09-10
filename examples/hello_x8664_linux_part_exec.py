#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

if __name__ == "__main__":
    def dump(ql, *args, **kw):
        ql.save(reg=False, cpu_context=True, snapshot="/tmp/snapshot.bin")
        ql.emu_stop()

    ql = Qiling(["rootfs/x8664_linux/bin/sleep_hello"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
    X64BASE = int(ql.profile.get("OS64", "load_address"), 16)
    ql.hook_address(dump, X64BASE + 0x1094)
    ql.run()

    ql = Qiling(["rootfs/x8664_linux/bin/sleep_hello"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DISASM)
    # load base address from profile file
    X64BASE = int(ql.profile.get("OS64", "load_address"), 16)
    ql.restore(snapshot="/tmp/snapshot.bin")
    # set execution starting and ending points
    begin_point = X64BASE + 0x109e
    end_point = X64BASE + 0x10bc
    ql.run(begin = begin_point, end = end_point)