#!/usr/bin/env python3
from qiling.extensions.qdb import Qdb
from qiling import *

if __name__ == "__main__":

    ql = Qiling(["rootfs/mips32el_linux/bin/mips32el_hello"], "rootfs/mips32el_linux")
    ql.hook_address(Qdb.attach, ql.os.elf_entry) # attach Qdb at entry point
    ql.run()
