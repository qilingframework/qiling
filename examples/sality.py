#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import UcError

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.const import POINTER, DWORD, STRING, HANDLE
from qiling.os.windows import utils
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *
from qiling.os.windows.dlls.kernel32.fileapi import _CreateFile

def init_unseen_symbols(ql: Qiling, address: int, name: str, ordinal: int, dll_name: str):
    ql.loader.import_symbols[address] = {
        "name": name,
        "ordinal": ordinal,
        "dll": dll_name.partition('.')[0]
    }

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
        if ql.amsint32_driver:
            return 0x13371337
        else:
            return (-1)
    else:
        ret = _CreateFile(ql, address, params)
    return ret

def _WriteFile(ql: Qiling, address: int, params):
    ret = 1
    hFile = params["hFile"]
    lpBuffer = params["lpBuffer"]
    nNumberOfBytesToWrite = params["nNumberOfBytesToWrite"]
    lpNumberOfBytesWritten = params["lpNumberOfBytesWritten"]
    #lpOverlapped = params["lpOverlapped"]

    if hFile == 0xfffffff5:
        s = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)
        ql.os.stdout.write(s)
        ql.os.stats.log_string(s.decode())
        ql.mem.write_ptr(lpNumberOfBytesWritten, nNumberOfBytesToWrite)
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
        ql.mem.write_ptr(lpNumberOfBytesWritten, nNumberOfBytesToWrite, 4)
    return ret

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
    if hFile == 0x13371337:
        buffer = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)
        try:
            nNumberOfBytesToWrite = utils.io_Write(ql.amsint32_driver, buffer)
            ql.mem.write_ptr(lpNumberOfBytesWritten, nNumberOfBytesToWrite, 4)
        except Exception:
            ql.log.exception("")
            r = False
        else:
            r = True

        return int(r)

    else:
        return _WriteFile(ql, address, params)


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
    try:
        hService = params["hService"]
        service_handle = ql.os.handle_manager.get(hService)
        if service_handle.name == "amsint32":
            if service_handle.name in ql.os.services:
                service_path = ql.os.services[service_handle.name]
                service_path = ql.os.path.transform_to_real_path(service_path)

                ql.amsint32_driver = Qiling([service_path], ql.rootfs, verbose=QL_VERBOSE.DEBUG)
                ntoskrnl = ql.amsint32_driver.loader.get_image_by_name("ntoskrnl.exe")
                assert ntoskrnl, 'ntoskernl.exe was not loaded'

                init_unseen_symbols(ql.amsint32_driver, ntoskrnl.base+0xb7695, b"NtTerminateProcess", 0, "ntoskrnl.exe")
                #ql.amsint32_driver.debugger= ":9999"
                try:
                    ql.amsint32_driver.load()
                    return 1
                except UcError as e:
                    print("Load driver error: ", e)
                    return 0
            else:
                return 0
        else:
            return 1
    except Exception as e:
        ql.log.exception("")
        print (e)


def hook_stop_address(ql):
    print(" >>>> Stop address: 0x%08x" % ql.arch.regs.arch_pc)
    ql.emu_stop()


if __name__ == "__main__":
    ql = Qiling(["../examples/rootfs/x86_windows/bin/sality.dll"], "../examples/rootfs/x86_windows", verbose=QL_VERBOSE.DEBUG, libcache=True)

    # for this module 
    ql.amsint32_driver = None

    # emulate some Windows API
    ql.os.set_api("CreateThread", hook_CreateThread)
    ql.os.set_api("CreateFileA", hook_CreateFileA)
    ql.os.set_api("WriteFile", hook_WriteFile)
    ql.os.set_api("StartServiceA", hook_StartServiceA)
    #init sality
    ql.hook_address(hook_stop_address, 0x40EFFB)
    ql.run()
    # run driver thread

    # execution is about to resume from 0x4053B2, which essentially jumps to ExitThread (kernel32.dll).
    # Set ExitThread exit code to 0
    ql.os.fcall = ql.os.fcall_select(STDCALL)
    ql.os.fcall.writeParams(((DWORD, 0),))

    ql.hook_address(hook_stop_address, 0x4055FA)
    ql.run(0x4053B2)
    ql.log.info("test kill thread")
    if ql.amsint32_driver:
        utils.io_Write(ql.amsint32_driver, ql.pack32(0xdeadbeef))

        # TODO: Should stop at 0x10423, but for now just stop at 0x0001066a
        ql.amsint32_driver.hook_address(hook_stop_address, 0x0001066a)

        # TODO: not sure whether this one is really STDCALL
        ql.amsint32_driver.os.fcall = ql.amsint32_driver.os.fcall_select(STDCALL)
        ql.amsint32_driver.os.fcall.writeParams(((DWORD, 0),))

        ql.amsint32_driver.run(begin=0x102D0)
