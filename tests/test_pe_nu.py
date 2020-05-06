#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys, random
import string as st
from binascii import unhexlify

sys.path.insert(0, "..")

from qiling import *
from qiling.exception import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from unicorn.x86_const import *

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
                output="default", log_dir='test_qlog', append="test")
    ql.log_split = True
    ql.run()
    del ql


def test_pe_win_x86_uselessdisk():
    ql = Qiling(["../examples/rootfs/x86_windows/bin/UselessDisk.bin"], "../examples/rootfs/x86_windows",
                output="debug")
    ql.run()
    del ql


def test_pe_win_x86_gandcrab():
    def stop(ql, default_values):
        print("Ok for now")
        ql.emu_stop()

    def randomize_config_value(ql, key, subkey):
        # https://en.wikipedia.org/wiki/Volume_serial_number
        # https://www.digital-detective.net/documents/Volume%20Serial%20Numbers.pdf
        if key == "VOLUME" and subkey == "serial_number":
            month = random.randint(0, 12)
            day = random.randint(0, 30)
            first = hex(month)[2:] + hex(day)[2:]
            seconds = random.randint(0, 60)
            milli = random.randint(0, 100)
            second = hex(seconds)[2:] + hex(milli)[2:]
            first_half = int(first, 16) + int(second, 16)
            hour = random.randint(0, 24)
            minute = random.randint(0, 60)
            third = hex(hour)[2:] + hex(minute)[2:]
            year = random.randint(2000, 2020)
            second_half = int(third, 16) + year
            result = int(hex(first_half)[2:] + hex(second_half)[2:], 16)
            ql.os.profile[key][subkey] = str(result)
        elif key == "USER" and subkey == "username":
            length = random.randint(0, 15)
            new_name = ""
            for i in range(length):
                new_name += random.choice(st.ascii_lowercase + st.ascii_uppercase)
            old_name = ql.os.profile[key][subkey]
            # update paths
            ql.os.profile[key][subkey] = new_name
            for path in ql.os.profile["PATH"]:
                val = ql.os.profile["PATH"][path].replace(old_name, new_name)
                ql.os.profile["PATH"][path] = val
        elif key == "SYSTEM" and subkey == "computername":
            length = random.randint(0, 15)
            new_name = ""
            for i in range(length):
                new_name += random.choice(st.ascii_lowercase + st.ascii_uppercase)
            ql.os.profile[key][subkey] = new_name
        else:
            raise QlErrorNotImplemented("[!] API not implemented")

    ql = Qiling(["../examples/rootfs/x86_windows/bin/GandCrab502.bin"], "../examples/rootfs/x86_windows",
                output="debug", profile="profiles/windows_gandcrab.ql")
    default_user = ql.os.profile["USER"]["username"]
    default_computer = ql.os.profile["SYSTEM"]["computername"]

    ql.hook_address(stop, 0x40860f, user_data=(default_user, default_computer))
    randomize_config_value(ql, "USER", "username")
    randomize_config_value(ql, "SYSTEM", "computername")
    randomize_config_value(ql, "VOLUME", "serial_number")
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
        ql.nprint("killerswtichfound")
        ql.log_console = False
        ql.nprint("No Print")
        ql.emu_stop()

    ql = Qiling(["../examples/rootfs/x86_windows/bin/wannacry.bin"], "../examples/rootfs/x86_windows")
    ql.hook_address(stop, 0x40819a)
    ql.run()
    del ql


def test_pe_win_al_khaser():
    ql = Qiling(["../examples/rootfs/x86_windows/bin/al-khaser.bin"], "../examples/rootfs/x86_windows")

    # The hooks are to remove the prints to file. It crashes. will debug why in the future
    def results(ql):

        if ql.reg.ebx == 1:
            print("[=] BAD")
        else:
            print("[=] GOOD ")
        ql.reg.eip = 0x402ee4

    ql.hook_address(results, 0x00402e66)
    # the program alloc 4 bytes and then tries to write 0x2cc bytes.
    # I have no idea of why this code should work without this patch
    ql.patch(0x00401984, b'\xb8\x04\x00\x00\x00')

    # This should call an interrupt. Other than we don't listen to interrupts, this interrupt is shit.
    ql.patch(0x0040145c, b'\x90' * 5)

    def end(ql):
        print("We are finally done")
        ql.emu_stop()

    ql.hook_address(end, 0x0040148d)

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
        lpDialogFunc = ql.unpack32(ql.mem.read(ql.reg.esp - 0x8, 4))
        # setup stack for DialogFunc
        ql.stack_push(0)
        ql.stack_push(1001)
        ql.stack_push(273)
        ql.stack_push(0)
        ql.stack_push(0x0401018)
        # force EIP to DialogFunc
        ql.reg.eip = lpDialogFunc

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
    test_pe_win_al_khaser()
