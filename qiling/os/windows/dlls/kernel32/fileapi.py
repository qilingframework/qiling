#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct, time, os
from shutil import copyfile
from datetime import datetime

from qiling.exception import *
from qiling.os.windows.const import *

from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.os.windows.utils import canonical_path
from qiling.exception import *
from qiling.os.windows.structs import *

dllname = 'kernel32_dll'

# DWORD GetFileType(
#   HANDLE hFile
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPCSTR': 'POINTER'})
def hook_FindFirstFileA(ql, address, params):
    filename = params['lpFileName']
    pointer = params['lpFindFileData']

    if filename == None:
        return INVALID_HANDLE_VALUE
    elif len(filename) >= MAX_PATH:
        return ERROR_INVALID_PARAMETER
    
    target_dir = os.path.join(ql.rootfs, filename.replace("\\", os.sep))
    print('TARGET_DIR = %s' % target_dir)    
    real_path = ql.os.transform_to_real_path(filename)
    # Verify the directory is in ql.rootfs to ensure no path traversal has taken place
    if not os.path.exists(real_path):
        ql.os.last_error = ERROR_FILE_NOT_FOUND
        return INVALID_HANDLE_VALUE

    # Check if path exists
    filesize = 0
    try:
        f = ql.os.fs_mapper.open(real_path, mode="r")
        filesize = os.path.getsize(real_path).to_bytes(8, byteorder="little")
    except FileNotFoundError:
        ql.os.last_error = ERROR_FILE_NOT_FOUND
        return INVALID_HANDLE_VALUE
    
    # Get size of the file
    file_size_low = (int.from_bytes(filesize, "little")) & 0xffffff
    file_size_high = (int.from_bytes(filesize, "little") >> 32)

    # Create a handle for the path
    new_handle = Handle(obj=f)
    ql.os.handle_manager.append(new_handle)

    # Spoof filetime values
    filetime = datetime.now().microsecond.to_bytes(8, byteorder="little")

    find_data = Win32FindData(
                ql, 
                FILE_ATTRIBUTE_NORMAL, 
                filetime, filetime, filetime, 
                file_size_high, file_size_low,
                0, 0, 
                filename,
                0, 0, 0, 0,)
                
    find_data.write(pointer)

    ret = new_handle.id
    return ret

# HANDLE FindFirstFileExA(
#  LPCSTR             lpFileName,
#  FINDEX_INFO_LEVELS fInfoLevelId,
#  FINDEX_SEARCH_OPS  fSearchOp,
#  LPVOID             lpSearchFilter,
#  DWORD              dwAdditionalFlags
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPCSTR': 'POINTER'})
def hook_FindFirstFileExA(ql, address, params):
    pass

# HANDLE FindNextFileA(
#  LPCSTR             lpFileName,
#  LPWIN32_FIND_DATAA lpFindFileData
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPCSTR': 'POINTER'})
def hook_FindNextFileA(ql, address, params):
    pass


# BOOL FindClose(
#    HANDLE hFindFile
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_FindClose(ql, address, params):
    pass


# BOOL ReadFile(
#   HANDLE       hFile,
#   LPVOID       lpBuffer,
#   DWORD        nNumberOfBytesToRead,
#   LPDWORD      lpNumberOfBytesRead,
#   LPOVERLAPPED lpOverlapped
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_ReadFile(ql, address, params):
    ret = 1
    hFile = params["hFile"]
    lpBuffer = params["lpBuffer"]
    nNumberOfBytesToRead = params["nNumberOfBytesToRead"]
    lpNumberOfBytesRead = params["lpNumberOfBytesRead"]
    lpOverlapped = params["lpOverlapped"]
    if hFile == STD_INPUT_HANDLE:
        if ql.os.automatize_input:
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
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
        ql.os.string_appearance(s.decode())
        ql.mem.write(lpNumberOfBytesWritten, ql.pack(nNumberOfBytesToWrite))
    else:
        f = ql.os.handle_manager.get(hFile)
        if f is None:
            # Invalid handle
            ql.os.last_error = ERROR_INVALID_HANDLE
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
    try:
        f = ql.os.fs_mapper.open(s_lpFileName, mode)
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
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
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CreateFileW(ql, address, params):
    ret = _CreateFile(ql, address, params, "CreateFileW")
    return ret


# DWORD GetTempPathW(
#   DWORD  nBufferLength,
#   LPWSTR lpBuffer
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetTempPathW(ql, address, params):
    temp = (ql.os.windir + "Temp" + "\\\x00").encode('utf-16le')
    dest = params["lpBuffer"]
    temp_path = os.path.join(ql.rootfs, "Windows", "Temp")
    if not os.path.exists(temp_path):
        os.makedirs(temp_path, 0o755)
    ql.mem.write(dest, temp)
    return len(temp)

# DWORD GetTempPathA(
#   DWORD  nBufferLength,
#   LPSTR lpBuffer
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "nBufferLength": DWORD,
    "lpBuffer": POINTER
})
def hook_GetTempPathA(ql, address, params):
    temp = (ql.os.windir + "Temp" + "\\\x00").encode('utf-8')
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
@winsdkapi(cc=STDCALL, dllname=dllname)
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
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_GetVolumeInformationW(ql, address, params):
    root = params["lpRootPathName"]
    if root != 0:
        pt_volume_name = params["lpVolumeNameBuffer"]
        if pt_volume_name != 0:
            # TODO implement
            volume_name = (ql.os.profile["VOLUME"]["name"] + "\x00").encode("utf-16le")

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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPCWSTR': 'POINTER'})
def hook_GetDriveTypeW(ql, address, params):
    path = params["lpRootPathName"]
    if path != 0:
        if path == ql.os.profile["PATH"]["systemdrive"]:
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
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPCWSTR': 'POINTER'})
def hook_GetDiskFreeSpaceW(ql, address, params):
    path = params["lpRootPathName"]
    if path == ql.os.profile["PATH"]["systemdrive"]:
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


# BOOL CreateDirectoryA(
#  LPCSTR                lpPathName,
#  LPSECURITY_ATTRIBUTES lpSecurityAttributes
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CreateDirectoryA(ql, address, params):
    path_name = params["lpPathName"]
    target_dir = os.path.join(ql.rootfs, path_name.replace("\\", os.sep))
    print('TARGET_DIR = %s' % target_dir)
    real_path = ql.os.transform_to_real_path(path_name)
    # Verify the directory is in ql.rootfs to ensure no path traversal has taken place
    if not os.path.exists(real_path):
        os.mkdir(real_path)
        return 1
    else:
        ql.os.last_error = ERROR_ALREADY_EXISTS
        return 0


# DWORD GetFileSize(
#  HANDLE  hFile,
#  LPDWORD lpFileSizeHigh
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'LPDWORD': 'DWORD'})
def hook_GetFileSize(ql, address, params):
    try:
        handle = ql.handle_manager.get(params['hFile'].file)
        return os.path.getsize(handle.name)
    except:
        ql.os.last_error = ERROR_INVALID_HANDLE 
        return 0xFFFFFFFF #INVALID_FILE_SIZE

# HANDLE CreateFileMappingA(
#   HANDLE                hFile,
#   LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
#   DWORD                 flProtect,
#   DWORD                 dwMaximumSizeHigh,
#   DWORD                 dwMaximumSizeLow,
#   LPCSTR                lpName
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "hFile": HANDLE,
    "lpFileMappingAttributes": POINTER,
    "flProtect": DWORD,
    "dwMaximumSizeHigh": DWORD,
    "dwMaximumSizeLow": DWORD,
    "lpName": STRING,
})
def hook_CreateFileMappingA(ql, address, params):
    hFile = params['hFile']
    lpName = params['lpName']
    new_handle = Handle(obj=hFile, name=lpName)
    ql.os.handle_manager.append(new_handle)
    ret = new_handle.id

    return ret

# HANDLE CreateFileMappingW(
#   HANDLE                hFile,
#   LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
#   DWORD                 flProtect,
#   DWORD                 dwMaximumSizeHigh,
#   DWORD                 dwMaximumSizeLow,
#   LPCWSTR               lpName
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "hFile": HANDLE,
    "lpFileMappingAttributes": POINTER,
    "flProtect": DWORD,
    "dwMaximumSizeHigh": DWORD,
    "dwMaximumSizeLow": DWORD,
    "lpName": WSTRING,
})
def hook_CreateFileMappingW(ql, address, params):
    hFile = params['hFile']
    lpName = params['lpName']
    new_handle = Handle(obj=hFile, name=lpName)
    ql.os.handle_manager.append(new_handle)
    ret = new_handle.id

    return ret

# LPVOID MapViewOfFile(
#   HANDLE hFileMappingObject,
#   DWORD  dwDesiredAccess,
#   DWORD  dwFileOffsetHigh,
#   DWORD  dwFileOffsetLow,
#   SIZE_T dwNumberOfBytesToMap
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "hFileMappingObject": HANDLE,
    "dwDesiredAccess": DWORD,
    "dwFileOffsetHigh": DWORD,
    "dwFileOffsetLow": DWORD,
    "dwNumberOfBytesToMap": DWORD
})
def hook_MapViewOfFile(ql, address, params):
    hFileMappingObject = params['hFileMappingObject']
    dwFileOffsetLow = params['dwFileOffsetLow']
    dwNumberOfBytesToMap = params['dwNumberOfBytesToMap']

    map_file_handle = ql.os.handle_manager.search_by_obj(hFileMappingObject)
    if map_file_handle is None:
        ret = ql.os.heap.alloc(dwNumberOfBytesToMap)
        new_handle = Handle(obj=hFileMappingObject, name=ret)
        ql.os.handle_manager.append(new_handle)
    else:
        ret = map_file_handle.name
    hFile = ql.os.handle_manager.get(hFileMappingObject).obj
    if ql.os.handle_manager.get(hFile):
        f = ql.os.handle_manager.get(hFile).obj
        if type(f) is file:
            f.seek(dwFileOffsetLow, 0)
            data = f.read(dwNumberOfBytesToMap)
            ql.mem.write(ret, data)
    return ret


# BOOL UnmapViewOfFile(
#   LPCVOID lpBaseAddress
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "lpBaseAddress": POINTER
})
def hook_UnmapViewOfFile(ql, address, params):
    lpBaseAddress = params['lpBaseAddress']

    map_file_hande = ql.os.handle_manager.search(lpBaseAddress)
    if not map_file_hande:
        return 0
    ql.os.heap.free(map_file_hande.name)
    ql.os.handle_manager.delete(map_file_hande.id)
    return 1



# BOOL CopyFileA(
#   LPCSTR lpExistingFileName,
#   LPCSTR lpNewFileName,
#   BOOL   bFailIfExists
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "lpExistingFileName": STRING,
    "lpNewFileName": STRING,
    "bFailIfExists": DWORD
})
def hook_CopyFileA(ql, address, params):
    lpExistingFileName = canonical_path(ql, params["lpExistingFileName"])
    lpNewFileName = canonical_path(ql, params["lpNewFileName"])
    bFailIfExists = params["bFailIfExists"]
    
    if bFailIfExists and os.path.exists(lpNewFileName):
        return 0
    copyfile(lpExistingFileName, lpNewFileName)
    return 1

# BOOL SetFileAttributesA(
#   LPCSTR lpFileName,
#   DWORD  dwFileAttributes
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={
    "lpFileName": STRING,
    "dwFileAttributes": DWORD
})
def hook_SetFileAttributesA(ql, address, params):
    return 1
