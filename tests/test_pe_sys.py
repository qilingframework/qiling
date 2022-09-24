#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import platform, sys, unittest
from typing import List

from unicorn import UcError

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_STOP, QL_VERBOSE
from qiling.os.const import POINTER, DWORD, HANDLE
from qiling.exception import QlErrorSyscallError
from qiling.os.windows import utils
from qiling.os.windows.wdk_const import *
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *
from qiling.os.windows.dlls.kernel32.fileapi import _CreateFile

if platform.system() == "Darwin" and platform.machine() == "arm64":
    sys.exit(0)

class PETest(unittest.TestCase):

    def test_pe_win_x86_sality(self):

        def init_unseen_symbols(ql, address, name, ordinal, dll_name):
            ql.loader.import_symbols[address] = {"name": name, "ordinal": ordinal, "dll": dll_name.split('.')[0] }
            ql.loader.import_address_table[dll_name][name] = address
            if ordinal != 0:
                ql.loader.import_address_table[dll_name][ordinal] = address


        # HANDLE CreateThread(
        #   LPSECURITY_ATTRIBUTES   lpThreadAttributes,
        #   SIZE_T                  dwStackSize,
        #   LPTHREAD_START_ROUTINE  lpStartAddress,
        #   __drv_aliasesMem LPVOID lpParameter,
        #   DWORD                   dwCreationFlags,
        #   LPDWORD                 lpThreadId
        # );
        @winsdkapi(cc=STDCALL, params={
            'lpThreadAttributes' : LPSECURITY_ATTRIBUTES,
            'dwStackSize'        : SIZE_T,
            'lpStartAddress'     : LPTHREAD_START_ROUTINE,
            'lpParameter'        : LPVOID,
            'dwCreationFlags'    : DWORD,
            'lpThreadId'         : LPDWORD
        })
        def hook_CreateThread(ql: Qiling, address: int, params):
            # set thread handle
            return 1

        # HANDLE CreateFileA(
        #   LPCSTR                lpFileName,
        #   DWORD                 dwDesiredAccess,
        #   DWORD                 dwShareMode,
        #   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        #   DWORD                 dwCreationDisposition,
        #   DWORD                 dwFlagsAndAttributes,
        #   HANDLE                hTemplateFile
        # );
        @winsdkapi(cc=STDCALL, params={
            'lpFileName'            : LPCSTR,
            'dwDesiredAccess'       : DWORD,
            'dwShareMode'           : DWORD,
            'lpSecurityAttributes'  : LPSECURITY_ATTRIBUTES,
            'dwCreationDisposition' : DWORD,
            'dwFlagsAndAttributes'  : DWORD,
            'hTemplateFile'         : HANDLE
        })
        def hook_CreateFileA(ql: Qiling, address: int, params):
            lpFileName = params["lpFileName"]

            if lpFileName.startswith("\\\\.\\"):
                if hasattr(ql, 'amsint32_driver'):
                    return 0x13371337

                return -1

            return _CreateFile(ql, address, params)

        @winsdkapi(cc=STDCALL, params={
            'hFile'                  : HANDLE,
            'lpBuffer'               : LPCVOID,
            'nNumberOfBytesToWrite'  : DWORD,
            'lpNumberOfBytesWritten' : LPDWORD,
            'lpOverlapped'           : LPOVERLAPPED
        })
        def hook_WriteFile(ql: Qiling, address: int, params):
            hFile = params["hFile"]
            lpBuffer = params["lpBuffer"]
            nNumberOfBytesToWrite = params["nNumberOfBytesToWrite"]
            lpNumberOfBytesWritten = params["lpNumberOfBytesWritten"]

            r = 1
            buffer = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)

            if hFile == 0x13371337:
                nNumberOfBytesToWrite = utils.io_Write(ql.amsint32_driver, buffer)

            elif hFile == 0xfffffff5:
                s = buffer.decode()

                ql.os.stdout.write(s)
                ql.os.stats.log_string(s)

            else:
                f = ql.os.handle_manager.get(hFile)

                if f is None:
                    ql.os.last_error = 0xffffffff
                    return 0

                f.obj.write(bytes(buffer))

            ql.mem.write_ptr(lpNumberOfBytesWritten, nNumberOfBytesToWrite, 4)

            return r

        # BOOL StartServiceA(
        #   SC_HANDLE hService,
        #   DWORD     dwNumServiceArgs,
        #   LPCSTR    *lpServiceArgVectors
        # );
        @winsdkapi(cc=STDCALL, params={
            'hService'            : SC_HANDLE,
            'dwNumServiceArgs'    : DWORD,
            'lpServiceArgVectors' : POINTER
        })
        def hook_StartServiceA(ql: Qiling, address: int, params):
            ql.test_set_api = True

            hService = params["hService"]
            service_handle = ql.os.handle_manager.get(hService)

            if service_handle.name != "amsint32":
                return 1

            if service_handle.name not in ql.os.services:
                return 0

            service_path = ql.os.services[service_handle.name]
            service_path = ql.os.path.transform_to_real_path(service_path)

            amsint32 = Qiling([service_path], ql.rootfs, verbose=QL_VERBOSE.DEBUG)
            ntoskrnl = amsint32.loader.get_image_by_name("ntoskrnl.exe")
            self.assertIsNotNone(ntoskrnl)

            init_unseen_symbols(amsint32, ntoskrnl.base + 0xb7695, b"NtTerminateProcess", 0, "ntoskrnl.exe")
            amsint32.log.info('Loading amsint32 driver')

            setattr(ql, 'amsint32_driver', amsint32)

            try:
                amsint32.run()
            except UcError as e:
                print("Load driver error: ", e)
                return 0
            else:
                return 1

        def hook_first_stop_address(ql: Qiling, stops: List[bool]):
            ql.log.info(f' >>>> First stop address: {ql.arch.regs.arch_pc:#010x}')
            stops[0] = True
            ql.emu_stop()

        def hook_second_stop_address(ql: Qiling, stops: List[bool]):
            ql.log.info(f' >>>> Second stop address: {ql.arch.regs.arch_pc:#010x}')
            stops[1] = True
            ql.emu_stop()

        def hook_third_stop_address(ql: Qiling, stops: List[bool]):
            ql.log.info(f' >>>> Third stop address: {ql.arch.regs.arch_pc:#010x}')
            stops[2] = True
            ql.emu_stop()

        stops = [False, False, False]

        ql = Qiling(["../examples/rootfs/x86_windows/bin/sality.dll"], "../examples/rootfs/x86_windows", verbose=QL_VERBOSE.DEBUG)

        # emulate some Windows API
        ql.os.set_api("CreateThread", hook_CreateThread)
        ql.os.set_api("CreateFileA", hook_CreateFileA)
        ql.os.set_api("WriteFile", hook_WriteFile)
        ql.os.set_api("StartServiceA", hook_StartServiceA)

        # run until first stop
        ql.hook_address(hook_first_stop_address, 0x40EFFB, stops)
        ql.run()

        # execution is about to resume from 0x4053B2, which essentially jumps to ExitThread (kernel32.dll).
        # Set ExitThread exit code to 0
        fcall = ql.os.fcall_select(STDCALL)
        fcall.writeParams(((DWORD, 0),))

        # run until second stop
        ql.hook_address(hook_second_stop_address, 0x4055FA, stops)
        ql.run(begin=0x4053B2)

        # asmint32 driver should have been initialized by now. otherwise we get an exception
        amsint32: Qiling = getattr(ql, 'amsint32_driver')

        # asmint32 driver init doesn't get to run far enough to initialize necessary data
        # structures. it is expected to fail.
        try:
            utils.io_Write(amsint32, ql.pack32(0xdeadbeef))
        except QlErrorSyscallError:
            pass

        # TODO: not sure whether this one is really STDCALL
        fcall = amsint32.os.fcall_select(STDCALL)
        fcall.writeParams(((DWORD, 0),))

        # run until third stop
        # TODO: Should stop at 0x10423, but for now just stop at 0x0001066a
        amsint32.hook_address(hook_third_stop_address, 0x0001066a, stops)
        amsint32.run(begin=0x102D0)

        self.assertTrue(stops[0])
        self.assertTrue(stops[1])
        self.assertTrue(stops[2])
        self.assertTrue(ql.test_set_api)


    def test_pe_win_x8664_driver(self):
        # Compiled sample from https://github.com/microsoft/Windows-driver-samples/tree/master/general/ioctl/wdm/sys
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/sioctl.sys"], "../examples/rootfs/x8664_windows", stop=QL_STOP.STACK_POINTER, libcache=True)

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

        ql.os.stats.clear()

        IOCTL_SIOCTL_METHOD_OUT_DIRECT = (40000, 0x901, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
        output_buffer_size = 0x1000
        in_buffer = b'Test input\0'
        Status, Information_value, output_data = utils.ioctl(ql, (IOCTL_SIOCTL_METHOD_OUT_DIRECT, output_buffer_size, in_buffer))

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

if __name__ == "__main__":
    unittest.main()
