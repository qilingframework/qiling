#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest

from unicorn import UcError

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.const import POINTER, DWORD, STRING, HANDLE
from qiling.os.windows.wdk_const import *
from qiling.os.windows.fncc import winsdkapi, STDCALL
from qiling.os.windows.dlls.kernel32.fileapi import _CreateFile


class PETest(unittest.TestCase):

    def hook_third_stop_address(self, ql):
        print(" >>>> Third Stop address: 0x%08x" % ql.reg.arch_pc)
        self.third_stop = True
        ql.emu_stop()


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
        @winsdkapi(cc=STDCALL, dllname='kernel32_dll')
        def hook_CreateThread(ql, address, params):
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
        @winsdkapi(cc=STDCALL, dllname='kernel32_dll', replace_params={
            "lpFileName": STRING,
            "dwDesiredAccess": DWORD,
            "dwShareMode": DWORD,
            "lpSecurityAttributes": POINTER,
            "dwCreationDisposition": DWORD,
            "dwFlagsAndAttributes": DWORD,
            "hTemplateFile": HANDLE
        })
        def hook_CreateFileA(ql, address, params):
            lpFileName = params["lpFileName"]
            if lpFileName.startswith("\\\\.\\"):
                if ql.amsint32_driver:
                    return 0x13371337
                else:
                    return (-1)
            else:
                ret = _CreateFile(ql, address, params, "CreateFileA")

            return ret

        def _WriteFile(ql, address, params):
            ret = 1
            hFile = params["hFile"]
            lpBuffer = params["lpBuffer"]
            nNumberOfBytesToWrite = params["nNumberOfBytesToWrite"]
            lpNumberOfBytesWritten = params["lpNumberOfBytesWritten"]
            #lpOverlapped = params["lpOverlapped"]

            if hFile == 0xfffffff5:
                s = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)
                ql.os.stdout.write(s)
                ql.os.utils.string_appearance(s.decode())
                ql.mem.write(lpNumberOfBytesWritten, ql.pack(nNumberOfBytesToWrite))
            else:
                f = ql.os.handle_manager.get(hFile)
                if f is None:
                    # Invalid handle
                    ql.os.last_error = 0xffffffff
                    return 0
                else:
                    f = f.obj
                buffer = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)
                f.write(bytes(buffer))
                ql.mem.write(lpNumberOfBytesWritten, ql.pack32(nNumberOfBytesToWrite))
            return ret

        @winsdkapi(cc=STDCALL, dllname='kernel32_dll', replace_params={
            "hFile": HANDLE,
            "lpBuffer": POINTER,
            "nNumberOfBytesToWrite": DWORD,
            "lpNumberOfBytesWritten": POINTER,
            "lpOverlapped": POINTER
        })
        def hook_WriteFile(ql, address, params):
            hFile = params["hFile"]
            lpBuffer = params["lpBuffer"]
            nNumberOfBytesToWrite = params["nNumberOfBytesToWrite"]
            lpNumberOfBytesWritten = params["lpNumberOfBytesWritten"]

            if hFile == 0x13371337:
                buffer = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)
                try:
                    r, nNumberOfBytesToWrite = ql.amsint32_driver.os.io_Write(buffer)
                    ql.mem.write(lpNumberOfBytesWritten, ql.pack32(nNumberOfBytesToWrite))
                except Exception:
                    print("Error")
                    r = 1
                if r:
                    return 1
                else:
                    return 0
            else:
                return _WriteFile(ql, address, params)


        # BOOL StartServiceA(
        #   SC_HANDLE hService,
        #   DWORD     dwNumServiceArgs,
        #   LPCSTR    *lpServiceArgVectors
        # );
        @winsdkapi(cc=STDCALL, dllname='advapi32_dll')
        def hook_StartServiceA(ql, address, params):
            hService = params["hService"]
            service_handle = ql.os.handle_manager.get(hService)
            ql.test_set_api = True
            if service_handle.name == "amsint32":
                if service_handle.name in ql.os.services:
                    service_path = ql.os.services[service_handle.name]
                    service_path = ql.os.path.transform_to_real_path(service_path)
                    ql.amsint32_driver = Qiling([service_path], ql.rootfs, verbose=QL_VERBOSE.DISASM)
                    init_unseen_symbols(ql.amsint32_driver, ql.amsint32_driver.loader.dlls["ntoskrnl.exe"]+0xb7695, b"NtTerminateProcess", 0, "ntoskrnl.exe")
                    print("load amsint32_driver")

                    try:
                        ql.amsint32_driver.run()
                        return 1
                    except UcError as e:
                        print("Load driver error: ", e)
                        return 0
                else:
                    return 0
            else:
                return 1


        def hook_first_stop_address(ql):
            print(" >>>> First Stop address: 0x%08x" % ql.reg.arch_pc)
            ql.first_stop = True    
            ql.emu_stop()


        def hook_second_stop_address(ql):
            print(" >>>> Second Stop address: 0x%08x" % ql.reg.arch_pc)
            ql.second_stop = True
            ql.emu_stop()


        ql = Qiling(["../examples/rootfs/x86_windows/bin/sality.dll"], "../examples/rootfs/x86_windows", verbose=QL_VERBOSE.DEBUG)
        ql.libcache = False
        ql.first_stop = False
        ql.second_stop = False
        self.third_stop = False
        # for this module 
        ql.amsint32_driver = None
        # emulate some Windows API
        ql.set_api("CreateThread", hook_CreateThread)
        ql.set_api("CreateFileA", hook_CreateFileA)
        ql.set_api("WriteFile", hook_WriteFile)
        ql.set_api("StartServiceA", hook_StartServiceA)
        #init sality
        ql.hook_address(hook_first_stop_address, 0x40EFFB)
        ql.run()
        # run driver thread

        # execution is about to resume from 0x4053B2, which essentially jumps to ExitThread (kernel32.dll).
        # Set ExitThread exit code to 0
        ql.os.fcall = ql.os.fcall_select(STDCALL)
        ql.os.fcall.writeParams(((DWORD, 0),))

        ql.hook_address(hook_second_stop_address, 0x4055FA)
        ql.run(begin=0x4053B2)
        print("test kill thread")
        if ql.amsint32_driver:
            ql.amsint32_driver.os.utils.io_Write(ql.pack32(0xdeadbeef))
            
            # TODO: Should stop at 0x10423, but for now just stop at 0x0001066a
            stop_addr = 0x0001066a
            ql.amsint32_driver.hook_address(self.hook_third_stop_address, stop_addr)

            # TODO: not sure whether this one is really STDCALL
            ql.amsint32_driver.os.fcall = ql.amsint32_driver.os.fcall_select(STDCALL)
            ql.amsint32_driver.os.fcall.writeParams(((DWORD, 0),))

            ql.amsint32_driver.run(begin=0x102D0)

        self.assertEqual(True, ql.first_stop)    
        self.assertEqual(True, ql.second_stop)
        self.assertEqual(True, self.third_stop)
        self.assertEqual(True, ql.test_set_api)


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

        ql.os.utils.clear_syscalls()

        IOCTL_SIOCTL_METHOD_OUT_DIRECT = (40000, 0x901, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
        output_buffer_size = 0x1000
        in_buffer = b'Test input\0'
        Status, Information_value, output_data = ql.os.utils.ioctl((IOCTL_SIOCTL_METHOD_OUT_DIRECT, output_buffer_size, in_buffer))

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