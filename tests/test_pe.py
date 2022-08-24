#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, random, sys, unittest, logging
import string as st

sys.path.append("..")
from qiling import Qiling
from qiling.const import *
from qiling.exception import *
from qiling.extensions import pipe
from qiling.loader.pe import QlPeCache
from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.mapper import QlFsMappedObject
# This is intended.
# See https://stackoverflow.com/questions/8804830/python-multiprocessing-picklingerror-cant-pickle-type-function
import multiprocess as mb
import traceback

# On Windows, the CPython GC is too conservative and may hold too
# many Unicorn objects (nearly 16GB) until free-ing them which may
# cause failure during tests.
#
# Use subprocess to make sure resources are free-ed when the subprocess
# is killed.
class QLWinSingleTest:

    def __init__(self, test):
        self._test = test

    def _run_test(self, results):
        try:
            results['result'] = self._test()
        except Exception as e:
            tb = traceback.format_exc()
            results['exception'] = tb
            results['result'] = False

    def run(self):
        with mb.Manager() as m:
            results = m.dict()
            p = mb.Process(target=QLWinSingleTest._run_test, args=(self, results))
            p.start()
            p.join()
            if "exception" not in results:
                return results['result']
            else:
                raise RuntimeError(f"\n\nGot an exception during subprocess:\n\n{results['exception']}")


class TestOut:
    def __init__(self):
        self.output = {}

    def write(self, string):
        key, value = string.split(b': ', 1)
        assert key not in self.output
        self.output[key] = value
        return len(string)

IS_FAST_TEST = 'QL_FAST_TEST' in os.environ

class PETest(unittest.TestCase):

    def test_pe_win_x8664_hello(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_hello.exe"], "../examples/rootfs/x8664_windows")
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x86_hello(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x86_windows/bin/x86_hello.exe"], "../examples/rootfs/x86_windows")
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x8664_file_upx(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_file_upx.exe"], "../examples/rootfs/x8664_windows")
            ql.run()
            del ql
            return True

        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x86_file_upx(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x86_windows/bin/x86_file_upx.exe"], "../examples/rootfs/x86_windows")
            ql.run()
            del ql
            return True

        self.assertTrue(QLWinSingleTest(_t).run())


    @unittest.skipIf(IS_FAST_TEST, 'fast test')
    def test_pe_win_x86_uselessdisk(self):
        def _t():
            class Fake_Drive(QlFsMappedObject):

                def read(self, size):
                    return random.randint(0, 256)
                
                def write(self, bs):
                    print(bs)
                    return len(bs)

                def fstat(self):
                    return -1
                
                def close(self):
                    return 0

            ql = Qiling(["../examples/rootfs/x86_windows/bin/UselessDisk.bin"], "../examples/rootfs/x86_windows",
                        verbose=QL_VERBOSE.DEBUG)
            ql.add_fs_mapper(r"\\.\PHYSICALDRIVE0", Fake_Drive())
            ql.run()
            del ql
            return True

        self.assertTrue(QLWinSingleTest(_t).run())


    @unittest.skipIf(IS_FAST_TEST, 'fast test')
    def test_pe_win_x86_gandcrab(self):
        def _t():
            def stop(ql: Qiling):
                ql.log.info("Ok for now")

                ql.emu_stop()

            def __rand_serialnum() -> str:
                """
                see: https://en.wikipedia.org/wiki/Volume_serial_number
                see: https://www.digital-detective.net/documents/Volume%20Serial%20Numbers.pdf
                """

                mon = random.randint(1, 12)
                day = random.randint(0, 30)
                word1 = (mon << 8) + day

                sec = random.randint(0, 59)
                ms = random.randint(0, 99)
                word2 = (sec << 8) + ms

                unified1 = word1 + word2

                hrs = random.randint(0, 23)
                mins = random.randint(0, 59)
                word1 = (hrs << 8) + mins

                yr = random.randint(2000, 2020)
                word2 = yr

                unified2 = word1 + word2

                return f'{unified1:04x}-{unified2:04x}'

            def __rand_name(minlen: int, maxlen: int) -> str:
                name_len = random.randint(minlen, maxlen)

                return ''.join(random.choices(st.ascii_lowercase + st.ascii_uppercase, k=name_len))


            ql = Qiling(["../examples/rootfs/x86_windows/bin/GandCrab502.bin"], "../examples/rootfs/x86_windows",
                        verbose=QL_VERBOSE.DEBUG, profile="profiles/windows_gandcrab_admin.ql")

            ql.hook_address(stop, 0x40860f)

            # randomize username
            old_uname = ql.os.profile['USER']['username']
            new_uname = __rand_name(3, 10)

            # update paths accordingly
            path_key = ql.os.profile['PATH']

            for p in path_key:
                path_key[p] = path_key[p].replace(old_uname, new_uname)

            ql.os.profile['USER']['username'] = new_uname

            # randomize computer name and serial number
            ql.os.profile['SYSTEM']['computername'] = __rand_name(5, 15)
            ql.os.profile['VOLUME']['serial_number'] = __rand_serialnum()

            ql.run()
            num_syscalls_admin = ql.os.stats.position
            del ql

            # RUN AS USER
            ql = Qiling(["../examples/rootfs/x86_windows/bin/GandCrab502.bin"], "../examples/rootfs/x86_windows", profile="profiles/windows_gandcrab_user.ql")

            ql.run()
            num_syscalls_user = ql.os.stats.position
            del ql

            # let's check that gandcrab behave takes a different path if a different environment is found
            return num_syscalls_admin != num_syscalls_user

        self.assertTrue(QLWinSingleTest(_t).run())

    def test_pe_win_x86_multithread(self):
        def _t():
            thread_id = -1

            def ThreadId_onEnter(ql: Qiling, address: int, params):
                nonlocal thread_id

                thread_id = ql.os.thread_manager.cur_thread.id

            ql = Qiling(["../examples/rootfs/x86_windows/bin/MultiThread.exe"], "../examples/rootfs/x86_windows")
            ql.os.set_api("GetCurrentThreadId", ThreadId_onEnter, QL_INTERCEPT.ENTER)
            ql.run()

            del ql

            return (1 <= thread_id < 255)

        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x8664_clipboard(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_clipboard_test.exe"], "../examples/rootfs/x8664_windows")
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x8664_tls(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_tls.exe"], "../examples/rootfs/x8664_windows")
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x86_getlasterror(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x86_windows/bin/GetLastError.exe"], "../examples/rootfs/x86_windows")
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x86_regdemo(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x86_windows/bin/RegDemo.exe"], "../examples/rootfs/x86_windows")
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x8664_fls(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x8664_windows/bin/Fls.exe"], "../examples/rootfs/x8664_windows", verbose=QL_VERBOSE.DEFAULT)
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x86_return_from_main_stackpointer(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x86_windows/bin/return_main.exe"], "../examples/rootfs/x86_windows", stop=QL_STOP.STACK_POINTER, libcache=True)
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x86_return_from_main_exit_trap(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x86_windows/bin/return_main.exe"], "../examples/rootfs/x86_windows", stop=QL_STOP.EXIT_TRAP, libcache=True)
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x8664_return_from_main_stackpointer(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_return_main.exe"], "../examples/rootfs/x8664_windows", stop=QL_STOP.STACK_POINTER, libcache=True)
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x8664_return_from_main_exit_trap(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_return_main.exe"], "../examples/rootfs/x8664_windows", stop=QL_STOP.EXIT_TRAP, libcache=True)
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    @unittest.skipIf(IS_FAST_TEST, 'fast test')
    def test_pe_win_x86_wannacry(self):
        def _t():
            def stop(ql):
                ql.log.info("killerswtichfound")
                ql.log.setLevel(logging.CRITICAL)
                ql.log.info("No Print")
                ql.emu_stop()

            ql = Qiling(["../examples/rootfs/x86_windows/bin/wannacry.bin"], "../examples/rootfs/x86_windows")
            ql.hook_address(stop, 0x40819a)
            ql.run()
            del ql
            return True

        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x86_NtQueryInformationSystem(self):
        def _t():
            ql = Qiling(
            ["../examples/rootfs/x86_windows/bin/NtQuerySystemInformation.exe"],
            "../examples/rootfs/x86_windows")
            ql.run()
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    @unittest.skipIf(IS_FAST_TEST, 'fast test')
    def test_pe_win_al_khaser(self):
        def _t():
            ql = Qiling(["../examples/rootfs/x86_windows/bin/al-khaser.bin"], "../examples/rootfs/x86_windows", verbose=QL_VERBOSE.OFF)

            # ole32 functions are not implemented yet; stop before the binary
            # starts using them
            ql.run(end=0x004016ae)

            del ql
            return True

        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x8664_customapi(self):
        def _t():
            set_api = None
            set_api_onenter = None
            set_api_onexit = None

            @winsdkapi(cc=CDECL, params={
                "str" : STRING
            })
            def my_puts64(ql: Qiling, address: int, params):
                nonlocal set_api
                print(f'[oncall] my_puts64: params = {params}')

                params["str"] = "Hello Hello Hello"
                ret = len(params["str"])
                set_api = ret

                return ret

            def my_onenter(ql: Qiling, address: int, params):
                nonlocal set_api_onenter
                print(f'[onenter] my_onenter: params = {params}')

                set_api_onenter = len(params["str"])

            def my_onexit(ql: Qiling, address: int, params, retval: int):
                nonlocal set_api_onexit
                print(f'[onexit] my_onexit: params = {params}')

                set_api_onexit = len(params["str"])

            def my_sandbox(path, rootfs):
                nonlocal set_api, set_api_onenter, set_api_onexit
                ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG)
                ql.os.set_api("puts", my_onenter, QL_INTERCEPT.ENTER)
                ql.os.set_api("puts", my_puts64, QL_INTERCEPT.CALL)
                ql.os.set_api("puts", my_onexit, QL_INTERCEPT.EXIT)
                ql.run()

                if 12 != set_api_onenter:
                    return False
                if 17 != set_api:
                    return False
                if 17 != set_api_onexit:
                    return False

                del ql
                return True

            return my_sandbox(["../examples/rootfs/x8664_windows/bin/x8664_hello.exe"], "../examples/rootfs/x8664_windows")
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x86_argv(self):
        def _t():
            
            target_txt = None

            def check_print(ql: Qiling, address: int, params):
                nonlocal target_txt
                ql.os.fcall = ql.os.fcall_select(CDECL)

                params = ql.os.resolve_fcall_params({
                    '_Options' : PARAM_INT64,
                    '_Stream'  : POINTER,
                    '_Format'  : STRING,
                    '_Locale'  : DWORD,
                    '_ArgList' : POINTER
                })

                format = params['_Format']
                arglist = params['_ArgList']

                count = format.count("%")
                fargs = [ql.mem.read_ptr(arglist + i * ql.arch.pointersize) for i in range(count)]

                try:
                    target_txt = ql.mem.string(fargs[1])
                except:
                    target_txt = ""

                return address, params

            ql = Qiling(["../examples/rootfs/x86_windows/bin/argv.exe"], "../examples/rootfs/x86_windows")
            ql.os.set_api('__stdio_common_vfprintf', check_print, QL_INTERCEPT.ENTER)
            ql.run()
            
            if target_txt.find("argv.exe"):
                target_txt = "argv.exe"
            
            if "argv.exe" != target_txt:
                return False
            
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x86_crackme(self):
        def _t():
            def force_call_dialog_func(ql):
                # get DialogFunc address
                lpDialogFunc = ql.unpack32(ql.mem.read(ql.arch.regs.esp - 0x8, 4))
                # setup stack for DialogFunc
                ql.stack_push(0)
                ql.stack_push(1001)
                ql.stack_push(273)
                ql.stack_push(0)
                ql.stack_push(0x0401018)
                # force EIP to DialogFunc
                ql.arch.regs.eip = lpDialogFunc

            def our_sandbox(path, rootfs):
                ql = Qiling(path, rootfs)
                ql.patch(0x004010B5, b'\x90\x90')
                ql.patch(0x004010CD, b'\x90\x90')
                ql.patch(0x0040110B, b'\x90\x90')
                ql.patch(0x00401112, b'\x90\x90')

                ql.os.stdin = pipe.SimpleStringBuffer()
                ql.os.stdin.write(b"Ea5yR3versing\n")

                ql.hook_address(force_call_dialog_func, 0x00401016)
                ql.run()
                del ql

            our_sandbox(["../examples/rootfs/x86_windows/bin/Easy_CrackMe.exe"], "../examples/rootfs/x86_windows")
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())
        

    def test_pe_win_x86_cmdln(self):
        def _t():
            ql = Qiling(
            ["../examples/rootfs/x86_windows/bin/cmdln32.exe", 'arg1', 'arg2 with spaces'],
            "../examples/rootfs/x86_windows")
            ql.os.stdout = TestOut()
            ql.run()
            expected_string = b'<C:\\Users\\Qiling\\Desktop\\cmdln32.exe arg1 "arg2 with spaces">\n'
            expected_keys = [b'_acmdln', b'_wcmdln', b'__p__acmdln', b'__p__wcmdln', b'GetCommandLineA', b'GetCommandLineW']
            for key in expected_keys:
                if not (key in ql.os.stdout.output):
                    return False
                if expected_string != ql.os.stdout.output[key]:
                    return False
            del ql
            return True

        self.assertTrue(QLWinSingleTest(_t).run())


    def test_pe_win_x8664_cmdln(self):
        def _t():
            ql = Qiling(
            ["../examples/rootfs/x8664_windows/bin/cmdln64.exe", 'arg1', 'arg2 with spaces'],
            "../examples/rootfs/x8664_windows")
            ql.os.stdout = TestOut()
            ql.run()
            expected_string = b'<C:\\Users\\Qiling\\Desktop\\cmdln64.exe arg1 "arg2 with spaces">\n'
            expected_keys = [b'_acmdln', b'_wcmdln', b'GetCommandLineA', b'GetCommandLineW']
            for key in expected_keys:
                if not (key in ql.os.stdout.output):
                    return False
                if expected_string != ql.os.stdout.output[key]:
                    return False
            del ql
            return True
        
        self.assertTrue(QLWinSingleTest(_t).run())

    class RefreshCache(QlPeCache):
        def restore(self, path):
            # If the cache entry exists, delete it
            fcache = self.create_filename(path)
            if os.path.exists(fcache):
                os.remove(fcache)
            return super().restore(path)

    class TestCache(QlPeCache):
        def __init__(self, testcase):
            super().__init__()
            self.testcase = testcase

        def restore(self, path):
            entry = super().restore(path)
            self.testcase.assertTrue(entry is not None)  # Check that it loaded a cache entry
            if path.endswith('msvcrt.dll'):
                self.testcase.assertEqual(len(entry.cmdlines), 2)
            else:
                self.testcase.assertEqual(len(entry.cmdlines), 0)
            self.testcase.assertIsInstance(entry.data, bytearray)
            return entry

        def save(self, path, entry):
            self.testcase.assertFalse(True)  # This should not be called!


    def test_pe_win_x8664_libcache(self):
        
        def _t():
            # First force the cache to be recreated
            ql = Qiling(["../examples/rootfs/x8664_windows/bin/cmdln64.exe",
                        'arg1', 'arg2 with spaces'],
                        "../examples/rootfs/x8664_windows",
                        libcache=PETest.RefreshCache(),
                        verbose=QL_VERBOSE.DEFAULT)
            ql.run()
            del ql

            # Now run with a special cache that validates that the 'real' cache will load,
            # and that the file is not written again
            ql = Qiling(["../examples/rootfs/x8664_windows/bin/cmdln64.exe",
                        'arg1', 'arg2 with spaces'],
                        "../examples/rootfs/x8664_windows",
                        libcache=PETest.TestCache(self),
                        verbose=QL_VERBOSE.DEFAULT)
            ql.run()
            del ql
            return True

        self.assertTrue(QLWinSingleTest(_t).run())

if __name__ == "__main__":
    unittest.main()
