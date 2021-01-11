#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import os, sys, unittest
from pathlib import Path
from unicorn import *

sys.path.append("..")
from qiling import *
from qiling.exception import *
from qiling.os.macos.events.macos_structs import *
from qiling.os.macos.structs import *

class MACHOTest(unittest.TestCase):
    def test_macho_macos_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_macos/bin/x8664_hello"], "../examples/rootfs/x8664_macos", output = "debug")
        ql.run()

    def test_macho_macos_superrootkit(self):
        # https://developer.apple.com/download/more
        # to download kernel.developmment
        def ls(ql, path):
            print("*"*80)
            print("[ demigod ] Call /usr/bin/ls:")
            getattr_addr = ql.os.heap.alloc(ctypes.sizeof(getattrlistbulk_args_t))
            alist_addr = ql.os.heap.alloc(ctypes.sizeof(attrlist_t))
            attrBufSize = 32768
            attrBuffer_addr = ql.os.heap.alloc(attrBufSize)
            retval_addr = ql.os.heap.alloc(8)
            
            alist = attrlist_t(ql, alist_addr)
            alist.bitmapcount = 5
            alist.reserved = 0
            alist.commonattr = 0x82079e0b
            alist.volattr = 0
            alist.dirattr = 0
            alist.fileattr = 557
            alist.forkattr = 0
            alist.updateToMem()

            getattr_arg = getattrlistbulk_args_t(ql, getattr_addr)
            getattr_arg.options = 8
            getattr_arg.dirfd = 5
            getattr_arg.alist = alist_addr
            getattr_arg.attributeBuffer = attrBuffer_addr
            getattr_arg.bufferSize = attrBufSize
            getattr_arg.updateToMem()

            ql.os.ev_manager.add_process(1234, "ls")
            ls = ql.os.ev_manager.proc_find(1234)
            ql.os.ev_manager.map_fd[getattr_arg.dirfd] = Path(path)
            ql.os.ev_manager.syscall(461, [ls.base, getattr_arg.base, retval_addr])
        
        def hook_stop(ql):
            ql.emu_stop()

        ql = Qiling(["../examples/rootfs/x8664_macos/kext/SuperRootkit.kext"], "../examples/rootfs/x8664_macos", output = "disasm")
        ql.hook_address(hook_stop, 0xffffff8000854800)

        try:
            ql.os.load_kext()
        except UcError as e:
            print("[!] Load driver error: %s" % e)
            sys.exit(-1)      

        ql.os.ev_manager.add_process(1337, "agent")
        ls(ql, ".")      

if __name__ == "__main__":
    unittest.main()

