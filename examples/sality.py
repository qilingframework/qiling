#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct, sys, logging

sys.path.append("..")
from qiling import *
from qiling.os.windows.fncc import *
from qiling.os.windows.dlls.kernel32.fileapi import _CreateFile
from qiling.os.windows.utils import canonical_path
from qiling.loader.utils import ql_pe_check_archtype


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
def sality_CreateThread(ql, address, params):
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
def sality_CreateFileA(ql, address, params):
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
    lpOverlapped = params["lpOverlapped"]
    if hFile == 0xfffffff5:
        s = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)
        ql.os.stdout.write(s)
        string_appearance(ql, s.decode())
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
def sality_WriteFile(ql, address, params):
    hFile = params["hFile"]
    lpBuffer = params["lpBuffer"]
    nNumberOfBytesToWrite = params["nNumberOfBytesToWrite"]
    lpNumberOfBytesWritten = params["lpNumberOfBytesWritten"]
    if hFile == 0x13371337:
        buffer = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)
        try:
            r, nNumberOfBytesToWrite = ql.amsint32_driver.os.io_Write(buffer)
            ql.mem.write(lpNumberOfBytesWritten, ql.pack32(nNumberOfBytesToWrite))
        except Exception as e:
            logging.exception("")
            print("Exception = %s" % str(e))
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
@winsdkapi(cc=STDCALL, dllname='kernel32_dll')
def sality_StartServiceA(ql, address, params):
    try:
        hService = params["hService"]
        service_handle = ql.os.handle_manager.get(hService)
        if service_handle.name == "amsint32":
            if service_handle.name in ql.os.services:
                service_path = ql.os.services[service_handle.name]
                service_path = canonical_path(ql, service_path)
                ql.amsint32_driver = Qiling([service_path], ql.rootfs, output="debug")
                init_unseen_symbols(ql.amsint32_driver, ql.amsint32_driver.loader.dlls["ntoskrnl.exe"]+0xb7695, b"NtTerminateProcess", 0, "ntoskrnl.exe")
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
        logging.exception("")
        print (e)


def hook_stop_address(ql):
    print(" >>>> Stop address: 0x%08x" % ql.reg.arch_pc)
    ql.emu_stop()


if __name__ == "__main__":
    ql = Qiling(["../examples/rootfs/x86_windows/bin/sality.dll"], "../examples/rootfs/x86_windows", output="debug")
    ql.libcache = True

    # for this module 
    ql.amsint32_driver = None
    # emulate some Windows API
    ql.set_api("CreateThread", sality_CreateThread)
    ql.set_api("CreateFileA", sality_CreateFileA)
    ql.set_api("WriteFile", sality_WriteFile)
    ql.set_api("StartServiceA", sality_StartServiceA)
    #init sality
    ql.hook_address(hook_stop_address, 0x40EFFB)
    ql.run()
    # run driver thread
    ql.os.set_function_args([0])
    ql.hook_address(hook_stop_address, 0x4055FA)
    ql.run(0x4053B2)
    logging.info("[+] test kill thread")
    if ql.amsint32_driver:
        ql.amsint32_driver.os.io_Write(struct.pack("<I", 0xdeadbeef))
        ql.amsint32_driver.hook_address(hook_stop_address, 0x10423)
        ql.amsint32_driver.set_function_args([0])
        ql.amsint32_driver.run(0x102D0)
