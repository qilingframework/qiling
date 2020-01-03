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

def test_pe_win_x8664_hello():
    ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_hello.exe"], "../examples/rootfs/x8664_windows", output = "default")
    ql.run()
    del ql


def test_pe_win_x86_hello():
    ql = Qiling(["../examples/rootfs/x86_windows/bin/x86_hello.exe"], "../examples/rootfs/x86_windows", output = "default")
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
    ql.reg_dir = "registry"
    ql.reg_diff = "reg_diff.json"
    ql.run()
    del ql

def test_pe_win_x8664_fls():
    ql = Qiling(["../examples/rootfs/x8664_windows/bin/Fls.exe"], "../examples/rootfs/x8664_windows", output = "default")
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
    @winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, params={
        "str": STRING
    })
    def my_puts64(ql, address, params):
        ret = 0
        ql.nprint("\n+++++++++\nMy Windows 64bit Windows API\n+++++++++\n")
        string = params["str"]
        ret = len(string)
        return ret


    def my_sandbox(path, rootfs):
        ql = Qiling(path, rootfs, output = "debug")
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

        def readline(self, end = b'\n'):
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
        lpDialogFunc = ql.unpack32(ql.mem_read(ql.sp - 0x8, 4))
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
    test_pe_win_x86_crackme()
    test_pe_win_x8664_customapi()
