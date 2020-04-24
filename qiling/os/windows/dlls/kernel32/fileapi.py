#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct, time, os

from qiling.os.windows.const import *
from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *

# DWORD GetFileType(
#   HANDLE hFile
# );
@winapi(cc=STDCALL, params={
    "hFile": HANDLE
})
def hook_GetFileType(ql, address, params):
    hFile = params["hFile"]
    if hFile == STD_INPUT_HANDLE or hFile == STD_OUTPUT_HANDLE or hFile == STD_ERROR_HANDLE:
        ret = FILE_TYPE_CHAR
    else:
        obj = ql.os.handle_manager.get(hFile)
        if obj is None:
            raise QlErrorNotImplemented("[!] API not implemented")
        else:
            # technically is not always a type_char but.. almost
            ret = FILE_TYPE_CHAR
    return ret


# HANDLE FindFirstFileA(
#  LPCSTR             lpFileName,
#  LPWIN32_FIND_DATAA lpFindFileData
# );
@winapi(cc=STDCALL, params={
    "lpFilename": POINTER,
    "lpFindFileData": POINTER
})
def hook_FindFirstFileA(ql, address, params):
    pass


# HANDLE FindNextFileA(
#  LPCSTR             lpFileName,
#  LPWIN32_FIND_DATAA lpFindFileData
# );
@winapi(cc=STDCALL, params={
    "lpFilename": POINTER,
    "lpFindFileData": POINTER
})
def hook_FindNextFileA(ql, address, params):
    pass


# BOOL FindClose(
#    HANDLE hFindFile
# );
@winapi(cc=STDCALL, params={
    "hFindFile": HANDLE,
})
def hook_FindClose(ql, address, params):
    pass


# BOOL ReadFile(
#   HANDLE       hFile,
#   LPVOID       lpBuffer,
#   DWORD        nNumberOfBytesToRead,
#   LPDWORD      lpNumberOfBytesRead,
#   LPOVERLAPPED lpOverlapped
# );
@winapi(cc=STDCALL, params={
    "hFile": HANDLE,
    "lpBuffer": POINTER,
    "nNumberOfBytesToRead": DWORD,
    "lpNumberOfBytesRead": POINTER,
    "lpOverlapped": POINTER
})
def hook_ReadFile(ql, address, params):
    ret = 1
    hFile = params["hFile"]
    lpBuffer = params["lpBuffer"]
    nNumberOfBytesToRead = params["nNumberOfBytesToRead"]
    lpNumberOfBytesRead = params["lpNumberOfBytesRead"]
    lpOverlapped = params["lpOverlapped"]
    if hFile == STD_INPUT_HANDLE:
        if ql.automatize_input:
            # TODO maybe insert a good random generation input
            s = (b"A" * (nNumberOfBytesToRead - 1)) + b"\x00"
        else:
            ql.dprint(D_INFO, "Insert input")
            s = ql.os.stdin.read(nNumberOfBytesToRead)
        slen = len(s)
        read_len = slen
        if slen > nNumberOfBytesToRead:
            s = s[:nNumberOfBytesToRead]
            read_len = nNumberOfBytesToRead
        ql.mem.write(lpBuffer, s)
        ql.mem.write(lpNumberOfBytesRead, ql.pack(read_len))
    else:
        f = ql.os.handle_manager.get(hFile).obj
        data = f.read(nNumberOfBytesToRead)
        ql.mem.write(lpBuffer, data)
        ql.mem.write(lpNumberOfBytesRead, ql.pack32(lpNumberOfBytesRead))
    return ret


# BOOL WriteFile(
#   HANDLE       hFile,
#   LPCVOID      lpBuffer,
#   DWORD        nNumberOfBytesToWrite,
#   LPDWORD      lpNumberOfBytesWritten,
#   LPOVERLAPPED lpOverlapped
# );
@winapi(cc=STDCALL, params={
    "hFile": HANDLE,
    "lpBuffer": POINTER,
    "nNumberOfBytesToWrite": DWORD,
    "lpNumberOfBytesWritten": POINTER,
    "lpOverlapped": POINTER
})
def hook_WriteFile(ql, address, params):
    ret = 1
    hFile = params["hFile"]
    lpBuffer = params["lpBuffer"]
    nNumberOfBytesToWrite = params["nNumberOfBytesToWrite"]
    lpNumberOfBytesWritten = params["lpNumberOfBytesWritten"]
    lpOverlapped = params["lpOverlapped"]
    if hFile == STD_OUTPUT_HANDLE:
        s = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)
        ql.os.stdout.write(s)
        ql.mem.write(lpNumberOfBytesWritten, ql.pack(nNumberOfBytesToWrite))
    else:
        f = ql.os.handle_manager.get(hFile)
        if f is None:
            # Invalid handle
            ql.os.last_error  = ERROR_INVALID_HANDLE
            return 0
        else:
            f = f.obj
        buffer = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)
        f.write(bytes(buffer))
        ql.mem.write(lpNumberOfBytesWritten, ql.pack32(nNumberOfBytesToWrite))
    return ret


def _CreateFile(ql, address, params, name):
    ret = INVALID_HANDLE_VALUE

    s_lpFileName = params["lpFileName"]
    dwDesiredAccess = params["dwDesiredAccess"]
    dwShareMode = params["dwShareMode"]
    lpSecurityAttributes = params["lpSecurityAttributes"]
    dwCreationDisposition = params["dwCreationDisposition"]
    dwFlagsAndAttributes = params["dwFlagsAndAttributes"]
    hTemplateFile = params["hTemplateFile"]

    # access mask DesiredAccess
    mode = ""
    if dwDesiredAccess & GENERIC_WRITE:
        mode += "wb"
    else:
        mode += "r"

    # create thread handle
    s_lpFileName = ql.os.transform_to_real_path(s_lpFileName)
    try:
        f = open(s_lpFileName.replace("\\", os.sep), mode)
    except FileNotFoundError:
        ql.os.last_error = ERROR_FILE_NOT_FOUND
        return INVALID_HANDLE_VALUE
    new_handle = Handle(obj=f)
    ql.os.handle_manager.append(new_handle)
    ret = new_handle.id

    return ret


# HANDLE CreateFileA(
#   LPCSTR                lpFileName,
#   DWORD                 dwDesiredAccess,
#   DWORD                 dwShareMode,
#   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
#   DWORD                 dwCreationDisposition,
#   DWORD                 dwFlagsAndAttributes,
#   HANDLE                hTemplateFile
# );
@winapi(cc=STDCALL, params={
    "lpFileName": STRING,
    "dwDesiredAccess": DWORD,
    "dwShareMode": DWORD,
    "lpSecurityAttributes": POINTER,
    "dwCreationDisposition": DWORD,
    "dwFlagsAndAttributes": DWORD,
    "hTemplateFile": HANDLE
})
def hook_CreateFileA(ql, address, params):
    ret = _CreateFile(ql, address, params, "CreateFileA")
    return ret


# HANDLE CreateFileW(
#   LPCWSTR                lpFileName,
#   DWORD                 dwDesiredAccess,
#   DWORD                 dwShareMode,
#   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
#   DWORD                 dwCreationDisposition,
#   DWORD                 dwFlagsAndAttributes,
#   HANDLE                hTemplateFile
# );
@winapi(cc=STDCALL, params={
    "lpFileName": WSTRING,
    "dwDesiredAccess": DWORD,
    "dwShareMode": DWORD,
    "lpSecurityAttributes": POINTER,
    "dwCreationDisposition": DWORD,
    "dwFlagsAndAttributes": DWORD,
    "hTemplateFile": HANDLE
})
def hook_CreateFileW(ql, address, params):
    ret = _CreateFile(ql, address, params, "CreateFileW")
    return ret


# DWORD GetTempPathW(
#   DWORD  nBufferLength,
#   LPWSTR lpBuffer
# );
@winapi(cc=STDCALL, params={
    "nBufferLength": DWORD,
    "lpBuffer": POINTER
})
def hook_GetTempPathW(ql, address, params):
    temp = (ql.os.profile["PATH"]["temp"] + "\\\x00").encode('utf-16le')
    dest = params["lpBuffer"]
    temp_path = os.path.join(ql.rootfs, "Windows", "Temp")
    if not os.path.exists(temp_path):
        os.makedirs(temp_path, 0o755)
    ql.mem.write(dest, temp)
    return len(temp)


# DWORD GetShortPathNameW(
#   LPCWSTR lpszLongPath,
#   LPWSTR  lpszShortPath,
#   DWORD   cchBuffer
# );
@winapi(cc=STDCALL, params={
    "lpszLongPath": WSTRING,
    "lpszShortPath": POINTER,
    "cchBuffer": DWORD,
})
def hook_GetShortPathNameW(ql, address, params):
    paths = params["lpszLongPath"].split("\\")
    dst = params["lpszShortPath"]
    max_size = params["cchBuffer"]
    res = paths[0]
    for path in paths[1:]:
        nameAndExt = path.split(".")
        name = nameAndExt[0]
        ext = "" if len(nameAndExt) == 1 else "." + nameAndExt[1]
        if len(name) > 8:
            name = name[:6] + "~1"
        res += "\\" + name + ext
    res += "\x00"
    res = res.encode("utf-16le")
    if max_size < len(res):
        return len(res)
    else:
        ql.mem.write(dst, res)
    return len(res) - 1


# BOOL GetVolumeInformationW(
#   LPCWSTR lpRootPathName,
#   LPWSTR  lpVolumeNameBuffer,
#   DWORD   nVolumeNameSize,
#   LPDWORD lpVolumeSerialNumber,
#   LPDWORD lpMaximumComponentLength,
#   LPDWORD lpFileSystemFlags,
#   LPWSTR  lpFileSystemNameBuffer,
#   DWORD   nFileSystemNameSize
# );
@winapi(cc=STDCALL, params={
    "lpRootPathName": POINTER,
    "lpVolumeNameBuffer": POINTER,
    "nVolumeNameSize": DWORD,
    "lpVolumeSerialNumber": POINTER,
    "lpMaximumComponentLength": POINTER,
    "lpFileSystemFlags": POINTER,
    "lpFileSystemNameBuffer": POINTER,
    "nFileSystemNameSize": DWORD
})
def hook_GetVolumeInformationW(ql, address, params):
    root_pt = params["lpRootPathName"]
    if root_pt != 0:
        root = read_wstring(ql, root_pt)
        pt_volume_name = params["lpVolumeNameBuffer"]
        if pt_volume_name != 0:
            # TODO implement
            volume_name = ("AAAABBBB"+"\x00").encode("utf-16le")

            ql.mem.write(pt_volume_name, volume_name)

        lpMaximumComponentLength = params["lpMaximumComponentLength"]
        if lpMaximumComponentLength != 0:
            ql.mem.write(lpMaximumComponentLength, (255).to_bytes(2, byteorder="little"))
        pt_serial_number = params["lpVolumeSerialNumber"]
        if pt_serial_number != 0:
            # TODO maybe has to be int
            serial_number = (ql.os.profile["VOLUME"]["serial_number"] + "\x00").encode("utf-16le")
            ql.mem.write(pt_serial_number, serial_number)
        pt_system_type = params["lpFileSystemNameBuffer"]
        pt_flag = params["lpFileSystemFlags"]
        if pt_flag != 0:
            # TODO implement
            flag = 0x00020000.to_bytes(4, byteorder="little")
            ql.mem.write(pt_flag, flag)
        if pt_system_type != 0:
            system_type = (ql.os.profile["VOLUME"]["type"] + "\x00").encode("utf-16le")
            ql.mem.write(pt_system_type, system_type)
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return 1


# UINT GetDriveTypeW(
#   LPCWSTR lpRootPathName
# );
@winapi(cc=STDCALL, params={
    "lpRootPathName": POINTER
})
def hook_GetDriveTypeW(ql, address, params):
    pointer = params["lpRootPathName"]
    if pointer != 0:
        path = read_wstring(ql, pointer)
        if path == ql.os.profile["VOLUME"]["PATH"]:
            return DRIVE_FIXED
        # TODO add configuration for drives
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return DRIVE_NO_ROOT_DIR


# BOOL GetDiskFreeSpaceW(
#   LPCWSTR lpRootPathName,
#   LPDWORD lpSectorsPerCluster,
#   LPDWORD lpBytesPerSector,
#   LPDWORD lpNumberOfFreeClusters,
#   LPDWORD lpTotalNumberOfClusters
# );
@winapi(cc=STDCALL, params={
    "lpRootPathName": WSTRING,
    "lpSectorsPerCluster": POINTER,
    "lpBytesPerSector": POINTER,
    "lpNumberOfFreeClusters": POINTER,
    "lpTotalNumberOfClusters": POINTER
})
def hook_GetDiskFreeSpaceW(ql, address, params):
    path = params["lpRootPathName"]
    if path == ql.os.profile["VOLUME"]["PATH"]:
        pt_sectors = params["lpSectorsPerCluster"]
        pt_bytes = params["lpBytesPerSector"]
        pt_free_clust = params["lpNumberOfFreeClusters"]
        pt_total_clust = params["lpTotalNumberOfClusters"]
        sectors = ql.os.profile.getint("VOLUME", "sectors_per_cluster").to_bytes(4, byteorder="little")
        bytes = ql.os.profile.getint("VOLUME", "bytes_per_sector").to_bytes(4, byteorder="little")
        free_clust = ql.os.profile.getint("VOLUME", "number_of_free_clusters").to_bytes(4, byteorder="little")
        total_clust = ql.os.profile.getint("VOLUME", "number_of_clusters").to_bytes(4, byteorder="little")
        ql.mem.write(pt_sectors, sectors)
        ql.mem.write(pt_bytes, bytes)
        ql.mem.write(pt_free_clust, free_clust)
        ql.mem.write(pt_total_clust, total_clust)
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
    return 0


#BOOL CreateDirectoryA(
#  LPCSTR                lpPathName,
#  LPSECURITY_ATTRIBUTES lpSecurityAttributes
#);
@winapi(cc=STDCALL, params={
    "lpPathName": STRING,
    "lpSecurityAttributes": POINTER
})
def hook_CreateDirectoryA(ql, address, params):
    try:
        target_dir = os.path.join(ql.rootfs, lpPathName.replace("\\", os.sep))
        print('TARGET_DIR = %s' % target_dir)
        ql.os.transform_to_real_path(lpPathName) 
        # Verify the directory is in ql.rootfs to ensure no path traversal has taken place
        if os.path.commonprefix(target_dir, ql.rootfs) != ql.rootfs:
            ql.dprint(D_INFO, 'CreateDirectoryA attempted to create dir outside of rootfs: "%s". Not creating.' % (target_dir))
            return 0
        else:
            os.mkdir()
            return 1
    except FileExistsError:
        ql.os.last_error = ERROR_ALREADY_EXISTS
        return 0
    finally:
        return 0

#DWORD GetFileSize(
#  HANDLE  hFile,
#  LPDWORD lpFileSizeHigh
#);
@winapi(cc=STDCALL, params={
    "hFile": HANDLE,
    "lpFileSizeHigh": DWORD,
})
def hook_GetFileSize(ql, address, params):
    try:
        handle = ql.handle_manager.get(params['hFile'].file)
        return os.path.getsize(handle.name)
    except:
        ql.os.last_error = ERROR_INVALID_HANDLE 
        return 0xFFFFFFFF #INVALID_FILE_SIZE
