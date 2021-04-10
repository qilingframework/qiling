#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import sys, unittest
from pathlib import Path

from unicorn import UcError

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.const import STRING
from qiling.os.macos.structs import *
from qiling.os.macos.fncc import macos_kernel_api

class MACHOTest(unittest.TestCase):
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

        def my_onenter(ql, address, params):
            print("\n")
            print("=" * 40)
            print(" Enter into my_onenter mode")
            print("params: %s" % params)
            print("=" * 40)
            print("\n")
            self.set_api_onenter = True
            return address, params

        def my_onexit(ql, address, params, retval):
            print("\n")
            print("=" * 40)
            print(" Enter into my_exit mode")
            print("params: %s" % params)
            print("=" * 40)
            print("\n")
            self.set_api_onexit = True

        @macos_kernel_api(passthru=True, params={
            "s": STRING,
        })
        def my__strlen(ql, address, params):
            self.set_api_strlen = True 
            return

        ql = Qiling(["../examples/rootfs/x8664_macos/kext/SuperRootkit.kext"], "../examples/rootfs/x8664_macos", verbose=QL_VERBOSE.DISASM)
        ql.set_api("_ipf_addv4", my_onenter, QL_INTERCEPT.ENTER)
        ql.set_api("_strncmp", my_onexit, QL_INTERCEPT.EXIT)
        ql.set_api("_strlen", my__strlen) 
        ql.hook_address(hook_stop, 0xffffff8000854800)

        try:
            ql.os.load_kext()
        except UcError as e:
            print("Load driver error: %s" % e)
            sys.exit(-1)

        ql.os.ev_manager.add_process(1337, "agent")
        ls(ql, ".")

        self.assertEqual(True, self.set_api_onenter)
        self.assertEqual(True, self.set_api_onexit)
        self.assertEqual(True, self.set_api_strlen)
        del ql
if __name__ == "__main__":
    unittest.main()

