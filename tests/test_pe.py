#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os, random, sys, unittest
import string as st
from binascii import unhexlify

sys.path.insert(0, "..")

from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.mapper import QlFsMappedObject
from unicorn.x86_const import *

class PETest(unittest.TestCase):

    def test_pe_win_x8664_hello(self):
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_hello.exe"], "../examples/rootfs/x8664_windows",
                    output="default")
        ql.run()
        del ql


    def test_pe_win_x86_hello(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/x86_hello.exe"], "../examples/rootfs/x86_windows",
                    output="default", profile="profiles/append_test.ql")
        ql.log_split = True
        ql.run()
        del ql


    def test_pe_win_x86_uselessdisk(self):
        if 'QL_FAST_TEST' in os.environ:
            return
        class Fake_Drive(QlFsMappedObject):

            def read(self, size):
                return random.randint(0, 256)
            
            def write(self, bs):
                print(bs)
                return

            def fstat(self):
                return -1
            
            def close(self):
                return 0

        ql = Qiling(["../examples/rootfs/x86_windows/bin/UselessDisk.bin"], "../examples/rootfs/x86_windows",
                    output="debug")
        ql.add_fs_mapper(r"\\.\PHYSICALDRIVE0", Fake_Drive())
        ql.run()
        del ql


    def test_pe_win_x86_gandcrab(self):
        if 'QL_FAST_TEST' in os.environ:
            return
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
                    output="debug", profile="profiles/windows_gandcrab_admin.ql")
        default_user = ql.os.profile["USER"]["username"]
        default_computer = ql.os.profile["SYSTEM"]["computername"]

        ql.hook_address(stop, 0x40860f, user_data=(default_user, default_computer))
        randomize_config_value(ql, "USER", "username")
        randomize_config_value(ql, "SYSTEM", "computername")
        randomize_config_value(ql, "VOLUME", "serial_number")
        num_syscalls_admin = ql.os.syscalls_counter
        ql.run()
        del ql

        # RUN AS USER
        ql = Qiling(["../examples/rootfs/x86_windows/bin/GandCrab502.bin"], "../examples/rootfs/x86_windows",
                    output="debug", profile="profiles/windows_gandcrab_user.ql")

        ql.run()
        num_syscalls_user = ql.os.syscalls_counter

        del ql

        ql = Qiling(["../examples/rootfs/x86_windows/bin/GandCrab502.bin"], "../examples/rootfs/x86_windows",
                    output="debug", profile="profiles/windows_gandcrab_russian_keyboard.ql")
        num_syscalls_russ = ql.os.syscalls_counter

        ql.run()
        del ql
        # let's check that gandcrab behave takes a different path if a different environment is found
        assert num_syscalls_admin != num_syscalls_user != num_syscalls_russ

    def test_pe_win_x86_multithread(self):
        def ThreadId_onEnter(ql, address, params):
            self.thread_id = ql.os.thread_manager.cur_thread.id
            return address, params

        ql = Qiling(["../examples/rootfs/x86_windows/bin/MultiThread.exe"], "../examples/rootfs/x86_windows")
        ql.set_api("GetCurrentThreadId", ThreadId_onEnter, QL_INTERCEPT.ENTER)
        ql.run()
        
        self.assertGreater(255, self.thread_id)
        self.assertLessEqual(1, self.thread_id)
        
        del self.thread_id
        del ql


    def test_pe_win_x86_clipboard(self):
        ql = Qiling(["../examples/rootfs/x8664_windows/bin//x8664_clipboard_test.exe"], "../examples/rootfs/x8664_windows")
        ql.run()
        del ql


    def test_pe_win_x86_tls(self):
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_tls.exe"], "../examples/rootfs/x8664_windows")
        ql.run()
        del ql


    def test_pe_win_x86_getlasterror(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/GetLastError.exe"], "../examples/rootfs/x86_windows")
        ql.run()
        del ql


    def test_pe_win_x86_regdemo(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/RegDemo.exe"], "../examples/rootfs/x86_windows")
        ql.run()
        del ql


    def test_pe_win_x8664_fls(self):
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/Fls.exe"], "../examples/rootfs/x8664_windows", output="default")
        ql.run()
        del ql


    def test_pe_win_x86_wannacry(self):
        if 'QL_FAST_TEST' in os.environ:
            return
        def stop(ql):
            ql.nprint("killerswtichfound")
            ql.console = False
            ql.nprint("No Print")
            ql.emu_stop()

        ql = Qiling(["../examples/rootfs/x86_windows/bin/wannacry.bin"], "../examples/rootfs/x86_windows")
        ql.hook_address(stop, 0x40819a)
        ql.run()
        del ql

    def test_pe_win_x86_NtQueryInformationSystem(self):
        ql = Qiling(
        ["../examples/rootfs/x86_windows/bin/NtQuerySystemInformation.exe"],
        "../examples/rootfs/x86_windows")
        ql.run()
        del ql

    def test_pe_win_al_khaser(self):
        if 'QL_FAST_TEST' in os.environ:
            return
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

        def end(ql):
            print("We are finally done")
            ql.emu_stop()

        ql.hook_address(end, 0x004016ae)

        ql.run()
        del ql


    def test_pe_win_x8664_customapi(self):
        @winsdkapi(cc=CDECL, replace_params={"str": STRING})
        def my_puts64(ql, address, params):
            ret = 0
            print("\n+++++++++ My Windows 64bit Windows API +++++++++\n")
            print("params: ", params)
            print("+++++++++\n")
            params["str"] = "Hello Hello Hello"
            ret = len(params["str"])
            self.set_api = len(params["str"])
            return ret

        def my_onenter(ql, address, params):
            print("\n+++++++++\nmy OnEnter")
            print("params: ", params)
            print("+++++++++\n")
            self.set_api_onenter = self.set_api = len( params["str"])
            return  address, params

        def my_onexit(ql, address, params):
            print("\n+++++++++\nmy OnExit")
            print("params: ", params)
            print("+++++++++\n")
            self.set_api_onexit = self.set_api = len( params["str"])

        def my_sandbox(path, rootfs):
            ql = Qiling(path, rootfs, output="debug")
            ql.set_api("puts", my_onenter, QL_INTERCEPT.ENTER)
            ql.set_api("puts", my_puts64)
            ql.set_api("puts", my_onexit, QL_INTERCEPT.EXIT)
            ql.run()
            
            self.assertEqual(17, self.set_api)
            self.assertEqual(12, self.set_api_onenter)
            self.assertEqual(17, self.set_api_onexit)
            
            del self.set_api
            del self.set_api_onenter
            del self.set_api_onexit
            del ql

        my_sandbox(["../examples/rootfs/x8664_windows/bin/x8664_hello.exe"], "../examples/rootfs/x8664_windows")


    def test_pe_win_x86_crackme(self):
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
    unittest.main()
