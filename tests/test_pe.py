#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, random, sys, unittest, logging
import string as st
from binascii import unhexlify

from unicorn.x86_const import *

sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.mapper import QlFsMappedObject
from qiling.os.windows.dlls.kernel32.fileapi import _CreateFile

class TestOut:
    def __init__(self):
        self.output = {}

    def write(self, string):
        key, value = string.split(b': ', 1)
        assert key not in self.output
        self.output[key] = value
        return len(string)


class PETest(unittest.TestCase):

    def test_pe_win_x8664_hello(self):
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_hello.exe"], "../examples/rootfs/x8664_windows",
                    output="default")
        ql.run()
        del ql


    def test_pe_win_x86_hello(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/x86_hello.exe"], "../examples/rootfs/x86_windows",
                    output="default", profile="profiles/append_test.ql", log_split=True)
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


    def test_pe_win_x86_return_from_main_stackpointer(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/return_main.exe"], "../examples/rootfs/x86_windows", libcache=True, stop_on_stackpointer=True)
        ql.run()
        del ql


    def test_pe_win_x86_return_from_main_exit_trap(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/return_main.exe"], "../examples/rootfs/x86_windows", libcache=True, stop_on_exit_trap=True)
        ql.run()
        del ql


    def test_pe_win_x8664_return_from_main_stackpointer(self):
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_return_main.exe"], "../examples/rootfs/x8664_windows", libcache=True, stop_on_stackpointer=True)
        ql.run()
        del ql


    def test_pe_win_x8664_return_from_main_exit_trap(self):
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_return_main.exe"], "../examples/rootfs/x8664_windows", libcache=True, stop_on_exit_trap=True)
        ql.run()
        del ql


    def test_pe_win_x86_wannacry(self):
        if 'QL_FAST_TEST' in os.environ:
            return
        def stop(ql):
            logging.info("killerswtichfound")
            logging.disable(level=logging.CRITICAL)
            logging.info("No Print")
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

        #ql.hook_address(results, 0x00402e66)
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

    def test_pe_win_x86_argv(self):
        def check_print(ql, address, params):
            if ql.pointersize == 8:
                _, _, p_format, _, p_args = ql.os.get_function_param(5)
            else:
                _, _, _, p_format, _, p_args = ql.os.get_function_param(6)
            fmt = ql.mem.string(p_format)
            count = fmt.count("%")
            params = []
            params_addr = p_args

            if count > 0:
                for i in range(count):
                        param = ql.mem.read(params_addr + i * ql.pointersize, ql.pointersize)
                        params.append(
                        ql.unpack(param)
                        )        

            self.target_txt = ""

            try:
                self.target_txt = ql.mem.string(params[1])       
            except:
                pass
            
            return  address, params

        ql = Qiling(["../examples/rootfs/x86_windows/bin/argv.exe"], "../examples/rootfs/x86_windows")
        ql.set_api('__stdio_common_vfprintf', check_print, QL_INTERCEPT.ENTER)
        ql.run()
        
        if self.target_txt.find("argv.exe"):
            self.target_txt = "argv.exe"
        
        self.assertEqual("argv.exe", self.target_txt)
        
        del self.target_txt
        del ql

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
        

    def test_pe_win_x8664_driver(self):
        # Compiled sample from https://github.com/microsoft/Windows-driver-samples/tree/master/general/ioctl/wdm/sys
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/sioctl.sys"], "../examples/rootfs/x8664_windows", libcache=True, stop_on_stackpointer=True)

        driver_object = ql.loader.driver_object

        # Verify that these start zeroed out
        majorfunctions = driver_object.MajorFunction
        self.assertEqual(majorfunctions[IRP_MJ_CREATE], 0)
        self.assertEqual(majorfunctions[IRP_MJ_CLOSE], 0)
        self.assertEqual(majorfunctions[IRP_MJ_DEVICE_CONTROL], 0)
        # And a DriverUnload
        self.assertEqual(driver_object.DriverUnload, 0)

        # Run the simulation
        ql.run()

        # Check that we have some MajorFunctions
        majorfunctions = driver_object.MajorFunction
        self.assertNotEqual(majorfunctions[IRP_MJ_CREATE], 0)
        self.assertNotEqual(majorfunctions[IRP_MJ_CLOSE], 0)
        self.assertNotEqual(majorfunctions[IRP_MJ_DEVICE_CONTROL], 0)
        # And a DriverUnload
        self.assertNotEqual(driver_object.DriverUnload, 0)

        ql.os.clear_syscalls()

        IOCTL_SIOCTL_METHOD_OUT_DIRECT = (40000, 0x901, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
        output_buffer_size = 0x1000
        in_buffer = b'Test input\0'
        Status, Information_value, output_data = ql.os.ioctl((IOCTL_SIOCTL_METHOD_OUT_DIRECT, output_buffer_size, in_buffer))

        expected_result = b'This String is from Device Driver !!!\x00'
        self.assertEqual(Status, 0)
        self.assertEqual(Information_value, len(expected_result))
        self.assertEqual(output_data, expected_result)

        # TODO:
        # - Call majorfunctions:
        #   - IRP_MJ_CREATE
        #   - IRP_MJ_CLOSE
        # - Call DriverUnload

        del ql

    def test_pe_win_x86_cmdln(self):
        ql = Qiling(
        ["../examples/rootfs/x86_windows/bin/cmdln32.exe", 'arg1', 'arg2 with spaces'],
        "../examples/rootfs/x86_windows")
        ql.stdout = TestOut()
        ql.run()
        expected_string = b'<C:\\Users\\Qiling\\Desktop\\cmdln32.exe arg1 "arg2 with spaces">\n'
        expected_keys = [b'_acmdln', b'_wcmdln', b'__p__acmdln', b'__p__wcmdln', b'GetCommandLineA', b'GetCommandLineW']
        for key in expected_keys:
            self.assertTrue(key in ql.stdout.output)
            self.assertEqual(expected_string, ql.stdout.output[key])
        del ql

    def test_pe_win_x8664_cmdln(self):
        ql = Qiling(
        ["../examples/rootfs/x8664_windows/bin/cmdln64.exe", 'arg1', 'arg2 with spaces'],
        "../examples/rootfs/x8664_windows")
        ql.stdout = TestOut()
        ql.run()
        expected_string = b'<C:\\Users\\Qiling\\Desktop\\cmdln64.exe arg1 "arg2 with spaces">\n'
        expected_keys = [b'_acmdln', b'_wcmdln', b'GetCommandLineA', b'GetCommandLineW']
        for key in expected_keys:
            self.assertTrue(key in ql.stdout.output)
            self.assertEqual(expected_string, ql.stdout.output[key])
        del ql


if __name__ == "__main__":
    unittest.main()
