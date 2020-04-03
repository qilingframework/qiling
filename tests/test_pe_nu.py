#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys

sys.path.insert(0, "..")

from qiling import *
from qiling.exception import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *

X86_WIN = unhexlify(
    'fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a01eb2668318b6f87ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5e8d5ffffff63616c6300')
X8664_WIN = unhexlify(
    'fc4881e4f0ffffffe8d0000000415141505251564831d265488b52603e488b52183e488b52203e488b72503e480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed5241513e488b52203e8b423c4801d03e8b80880000004885c0746f4801d0503e8b48183e448b40204901d0e35c48ffc93e418b34884801d64d31c94831c0ac41c1c90d4101c138e075f13e4c034c24084539d175d6583e448b40244901d0663e418b0c483e448b401c4901d03e418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a3e488b12e949ffffff5d49c7c1000000003e488d95fe0000003e4c8d850f0100004831c941ba45835607ffd54831c941baf0b5a256ffd548656c6c6f2c2066726f6d204d534621004d657373616765426f7800')


def test_pe_win_x8664_hello():
    ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_hello.exe"], "../examples/rootfs/x8664_windows",
                output="default")
    ql.run()
    del ql


def test_pe_win_x86_hello():
    ql = Qiling(["../examples/rootfs/x86_windows/bin/x86_hello.exe"], "../examples/rootfs/x86_windows",
                output="default", log_dir='.')
    ql.log_split = True            
    ql.run()
    del ql


def test_pe_win_x86_uselessdisk():
    ql = Qiling(["../examples/rootfs/x86_windows/bin/UselessDisk.bin"], "../examples/rootfs/x86_windows",
                output="debug")
    ql.run()
    del ql


def test_pe_win_x86_gandcrab():
    def stop(ql):
        print("Ok for now")
        ql.uc.emu_stop()

    ql = Qiling(["../examples/rootfs/x86_windows/bin/GandCrab502.bin"], "../examples/rootfs/x86_windows",
                output="debug")
    ql.hook_address(stop, 0x1001a3c6)
    ql.run()
    del ql


def test_pe_win_x86_multithread():
    ql = Qiling(["../examples/rootfs/x86_windows/bin/MultiThread.exe"], "../examples/rootfs/x86_windows")
    ql.run()
    del ql


def test_pe_win_x86_clipboard():
    ql = Qiling(["../examples/rootfs/x8664_windows/bin//x8664_clipboard_test.exe"], "../examples/rootfs/x8664_windows")
    ql.run()
    del ql


def test_pe_win_x86_tls():
    ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_tls.exe"], "../examples/rootfs/x8664_windows")
    ql.run()
    del ql


def test_pe_win_x86_getlasterror():
    ql = Qiling(["../examples/rootfs/x86_windows/bin/GetLastError.exe"], "../examples/rootfs/x86_windows")
    ql.run()
    del ql


def test_pe_win_x86_regdemo():
    ql = Qiling(["../examples/rootfs/x86_windows/bin/RegDemo.exe"], "../examples/rootfs/x86_windows")
    ql.run()
    del ql


def test_pe_win_x8664_fls():
    ql = Qiling(["../examples/rootfs/x8664_windows/bin/Fls.exe"], "../examples/rootfs/x8664_windows", output="default")
    ql.run()
    del ql


def test_pe_win_x86_wannacry():
    def stop(ql):
        print("killerswtichfound")
        ql.uc.emu_stop()

    ql = Qiling(["../examples/rootfs/x86_windows/bin/wannacry.bin"], "../examples/rootfs/x86_windows")
    ql.hook_address(stop, 0x40819a)
    ql.run()
    del ql


def test_pe_win_x8664_customapi():
    @winapi(cc=CDECL, params={
        "str": STRING
    })
    def my_puts64(ql, address, params):
        ret = 0
        ql.nprint("\n+++++++++\nMy Windows 64bit Windows API\n+++++++++\n")
        string = params["str"]
        ret = len(string)
        return ret

    def my_sandbox(path, rootfs):
        ql = Qiling(path, rootfs, output="debug")
        ql.set_syscall("puts", my_puts64)
        ql.run()
        del ql

    my_sandbox(["../examples/rootfs/x8664_windows/bin/x8664_hello.exe"], "../examples/rootfs/x8664_windows")


def test_pe_win_x86_crackme():
    class StringBuffer:
        def __init__(self):
            self.buffer = b''

        def read(self, n):
            ret = self.buffer[:n]
            self.buffer = self.buffer[n:]
            return ret

        def readline(self, end=b'\n'):
            ret = b''
            while True:
                c = self.read(1)
                ret += c
                if c == end:
                    break
            return ret

        def write(self, string):
            self.buffer += string
            return len(string)

    def force_call_dialog_func(ql):
        # get DialogFunc address
        lpDialogFunc = ql.unpack32(ql.mem.read(ql.sp - 0x8, 4))
        # setup stack for DialogFunc
        ql.stack_push(0)
        ql.stack_push(1001)
        ql.stack_push(273)
        ql.stack_push(0)
        ql.stack_push(0x0401018)
        # force EIP to DialogFunc
        ql.pc = lpDialogFunc

    def our_sandbox(path, rootfs):
        ql = Qiling(path, rootfs)
        ql.patch(0x004010B5, b'\x90\x90')
        ql.patch(0x004010CD, b'\x90\x90')
        ql.patch(0x0040110B, b'\x90\x90')
        ql.patch(0x00401112, b'\x90\x90')
        ql.stdin = StringBuffer()
        ql.stdin.write(b"Ea5yR3versing\n")
        ql.hook_address(force_call_dialog_func, 0x00401016)
        ql.run()
        del ql

    our_sandbox(["../examples/rootfs/x86_windows/bin/Easy_CrackMe.exe"], "../examples/rootfs/x86_windows")


if __name__ == "__main__":
    test_pe_win_x8664_hello()
    test_pe_win_x86_hello()
    test_pe_win_x86_multithread()
    test_pe_win_x86_clipboard()
    test_pe_win_x86_tls()
    test_pe_win_x86_wannacry()
    test_pe_win_x8664_fls()
    test_pe_win_x86_getlasterror()
    test_pe_win_x86_regdemo()
    test_pe_win_x8664_customapi()
    test_pe_win_x86_uselessdisk()
    test_pe_win_x86_crackme()
    test_pe_win_x86_gandcrab()
