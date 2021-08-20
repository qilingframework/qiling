#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from shutil import copyfile
from datetime import datetime

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.handle import Handle
from qiling.os.windows.structs import Win32FindData

# DWORD GetFileType(
#   HANDLE hFile
# );
@winsdkapi(cc=STDCALL, params={
    'hFile' : HANDLE
})
def hook_GetFileType(ql: Qiling, address: int, params):
    hFile = params["hFile"]

    if hFile in (STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE):
        ret = FILE_TYPE_CHAR
    else:
        obj = ql.os.handle_manager.get(hFile)

        if obj is None:
            raise QlErrorNotImplemented("API not implemented")
        else:
            # technically is not always a type_char but.. almost
            ret = FILE_TYPE_CHAR

    return ret

# HANDLE FindFirstFileA(
#  LPCSTR             lpFileName,
#  LPWIN32_FIND_DATAA lpFindFileData
# );
@winsdkapi(cc=STDCALL, params={
    'lpFileName'     : LPCSTR,
    'lpFindFileData' : LPWIN32_FIND_DATAA
})
def hook_FindFirstFileA(ql: Qiling, address: int, params):
    filename = params['lpFileName']
    pointer = params['lpFindFileData']

    if filename == 0:
        return INVALID_HANDLE_VALUE
    elif len(filename) >= MAX_PATH:
        return ERROR_INVALID_PARAMETER

    target_dir = os.path.join(ql.rootfs, filename.replace("\\", os.sep))
    ql.log.info('TARGET_DIR = %s' % target_dir)
    real_path = ql.os.path.transform_to_real_path(filename)

    # Verify the directory is in ql.rootfs to ensure no path traversal has taken place
    if not os.path.exists(real_path):
        ql.os.last_error = ERROR_FILE_NOT_FOUND
        return INVALID_HANDLE_VALUE

    # Check if path exists
    filesize = 0
    try:
        f = ql.os.fs_mapper.open(real_path, "r")
        filesize = os.path.getsize(real_path)
    except FileNotFoundError:
        ql.os.last_error = ERROR_FILE_NOT_FOUND
        return INVALID_HANDLE_VALUE

    # Get size of the file
    file_size_low = filesize & 0xffffff
    file_size_high = filesize >> 32

    # Create a handle for the path
    new_handle = Handle(obj=f)
    ql.os.handle_manager.append(new_handle)

    # Spoof filetime values
    filetime = ql.pack64(datetime.now().microsecond)

    find_data = Win32FindData(
                ql,
                FILE_ATTRIBUTE_NORMAL,
                filetime, filetime, filetime,
                file_size_high, file_size_low,
                0, 0,
                filename,
                0, 0, 0, 0,)

    find_data.write(pointer)

    return new_handle.id

# HANDLE FindFirstFileExA(
#  LPCSTR             lpFileName,
#  FINDEX_INFO_LEVELS fInfoLevelId,
#  FINDEX_SEARCH_OPS  fSearchOp,
#  LPVOID             lpSearchFilter,
#  DWORD              dwAdditionalFlags
# );
@winsdkapi(cc=STDCALL, params={
    'lpFileName'        : LPCSTR,
    'fInfoLevelId'      : DWORD,    # FINDEX_INFO_LEVELS
    'lpFindFileData'    : LPVOID,
    'fSearchOp'         : DWORD,    # FINDEX_SEARCH_OPS
    'lpSearchFilter'    : LPVOID,
    'dwAdditionalFlags' : DWORD
})
def hook_FindFirstFileExA(ql: Qiling, address: int, params):
    pass

# HANDLE FindNextFileA(
#  LPCSTR             lpFileName,
#  LPWIN32_FIND_DATAA lpFindFileData
# );
@winsdkapi(cc=STDCALL, params={
    'hFindFile'      : HANDLE,
    'lpFindFileData' : LPWIN32_FIND_DATAA
})
def hook_FindNextFileA(ql: Qiling, address: int, params):
    pass

# BOOL FindClose(
#    HANDLE hFindFile
# );
@winsdkapi(cc=STDCALL, params={
    'hFindFile' : HANDLE
})
def hook_FindClose(ql: Qiling, address: int, params):
    pass

# BOOL ReadFile(
#   HANDLE       hFile,
#   LPVOID       lpBuffer,
#   DWORD        nNumberOfBytesToRead,
#   LPDWORD      lpNumberOfBytesRead,
#   LPOVERLAPPED lpOverlapped
# );
@winsdkapi(cc=STDCALL, params={
    'hFile'                : HANDLE,
    'lpBuffer'             : LPVOID,
    'nNumberOfBytesToRead' : DWORD,
    'lpNumberOfBytesRead'  : LPDWORD,
    'lpOverlapped'         : LPOVERLAPPED
})
def hook_ReadFile(ql: Qiling, address: int, params):
    hFile = params["hFile"]
    lpBuffer = params["lpBuffer"]
    nNumberOfBytesToRead = params["nNumberOfBytesToRead"]
    lpNumberOfBytesRead = params["lpNumberOfBytesRead"]

    if hFile == STD_INPUT_HANDLE:
        if ql.os.automatize_input:
            # TODO maybe insert a good random generation input
            s = (b"A" * (nNumberOfBytesToRead - 1)) + b"\x00"
        else:
            ql.log.debug("Insert input")
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

    return 1

# BOOL WriteFile(
#   HANDLE       hFile,
#   LPCVOID      lpBuffer,
#   DWORD        nNumberOfBytesToWrite,
#   LPDWORD      lpNumberOfBytesWritten,
#   LPOVERLAPPED lpOverlapped
# );
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

    if hFile == STD_OUTPUT_HANDLE:
        s = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)
        ql.os.stdout.write(s)
        ql.os.utils.string_appearance(s.decode())
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

    return 1

def _CreateFile(ql: Qiling, address: int, params):
    s_lpFileName = params["lpFileName"]
    dwDesiredAccess = params["dwDesiredAccess"]
    # dwShareMode = params["dwShareMode"]
    # lpSecurityAttributes = params["lpSecurityAttributes"]
    # dwCreationDisposition = params["dwCreationDisposition"]
    # dwFlagsAndAttributes = params["dwFlagsAndAttributes"]
    # hTemplateFile = params["hTemplateFile"]

    # access mask DesiredAccess
    mode = ""
    if dwDesiredAccess & GENERIC_WRITE:
        mode += "wb"
    else:
        mode += "r"

    try:
        f = ql.os.fs_mapper.open(s_lpFileName, mode)
    except FileNotFoundError:
        ql.os.last_error = ERROR_FILE_NOT_FOUND
        return INVALID_HANDLE_VALUE

    new_handle = Handle(obj=f)
    ql.os.handle_manager.append(new_handle)

    return new_handle.id

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
    return _CreateFile(ql, address, params)

# HANDLE CreateFileW(
#   LPCWSTR                lpFileName,
#   DWORD                 dwDesiredAccess,
#   DWORD                 dwShareMode,
#   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
#   DWORD                 dwCreationDisposition,
#   DWORD                 dwFlagsAndAttributes,
#   HANDLE                hTemplateFile
# );
@winsdkapi(cc=STDCALL, params={
    'lpFileName'            : LPCWSTR,
    'dwDesiredAccess'       : DWORD,
    'dwShareMode'           : DWORD,
    'lpSecurityAttributes'  : LPSECURITY_ATTRIBUTES,
    'dwCreationDisposition' : DWORD,
    'dwFlagsAndAttributes'  : DWORD,
    'hTemplateFile'         : HANDLE
})
def hook_CreateFileW(ql: Qiling, address: int, params):
    return  _CreateFile(ql, address, params)

# DWORD GetTempPathW(
#   DWORD  nBufferLength,
#   LPWSTR lpBuffer
# );
@winsdkapi(cc=STDCALL, params={
    'nBufferLength' : DWORD,
    'lpBuffer'      : LPWSTR
})
def hook_GetTempPathW(ql: Qiling, address: int, params):
    temp_path = os.path.join(ql.rootfs, "Windows", "Temp")

    if not os.path.exists(temp_path):
        os.makedirs(temp_path, 0o755)

    dest = params["lpBuffer"]
    temp = (ql.os.windir + "Temp" + "\\\x00").encode('utf-16le')
    ql.mem.write(dest, temp)

    return len(temp)

# DWORD GetTempPathA(
#   DWORD  nBufferLength,
#   LPSTR lpBuffer
# );
@winsdkapi(cc=STDCALL, params={
    'nBufferLength' : DWORD,
    'lpBuffer'      : LPSTR
})
def hook_GetTempPathA(ql: Qiling, address: int, params):
    temp_path = os.path.join(ql.rootfs, "Windows", "Temp")

    if not os.path.exists(temp_path):
        os.makedirs(temp_path, 0o755)

    dest = params["lpBuffer"]
    temp = (ql.os.windir + "Temp" + "\\\x00").encode('utf-8')
    ql.mem.write(dest, temp)

    return len(temp)

# DWORD GetShortPathNameW(
#   LPCWSTR lpszLongPath,
#   LPWSTR  lpszShortPath,
#   DWORD   cchBuffer
# );
@winsdkapi(cc=STDCALL, params={
    'lpszLongPath'  : LPCWSTR,
    'lpszShortPath' : LPWSTR,
    'cchBuffer'     : DWORD
})
def hook_GetShortPathNameW(ql: Qiling, address: int, params):
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
@winsdkapi(cc=STDCALL, params={
    'lpRootPathName'           : LPCWSTR,
    'lpVolumeNameBuffer'       : LPWSTR,
    'nVolumeNameSize'          : DWORD,
    'lpVolumeSerialNumber'     : LPDWORD,
    'lpMaximumComponentLength' : LPDWORD,
    'lpFileSystemFlags'        : LPDWORD,
    'lpFileSystemNameBuffer'   : LPWSTR,
    'nFileSystemNameSize'      : DWORD
})
def hook_GetVolumeInformationW(ql: Qiling, address: int, params):
    root = params["lpRootPathName"]

    if root == 0:
        raise QlErrorNotImplemented("API not implemented")

    pt_volume_name = params["lpVolumeNameBuffer"]

    if pt_volume_name != 0:
        # TODO implement
        volume_name = (ql.os.profile["VOLUME"]["name"] + "\x00").encode("utf-16le")

        ql.mem.write(pt_volume_name, volume_name)

    lpMaximumComponentLength = params["lpMaximumComponentLength"]
    if lpMaximumComponentLength != 0:
        ql.mem.write(lpMaximumComponentLength, ql.pack16(255))

    pt_serial_number = params["lpVolumeSerialNumber"]
    if pt_serial_number != 0:
        # TODO maybe has to be int
        serial_number = (ql.os.profile["VOLUME"]["serial_number"] + "\x00").encode("utf-16le")
        ql.mem.write(pt_serial_number, serial_number)

    pt_system_type = params["lpFileSystemNameBuffer"]
    pt_flag = params["lpFileSystemFlags"]

    if pt_flag != 0:
        # TODO implement
        ql.mem.write(pt_flag, ql.pack32(0x00020000))

    if pt_system_type != 0:
        system_type = (ql.os.profile["VOLUME"]["type"] + "\x00").encode("utf-16le")
        ql.mem.write(pt_system_type, system_type)

    return 1

# UINT GetDriveTypeW(
#   LPCWSTR lpRootPathName
# );
@winsdkapi(cc=STDCALL, params={
    'lpRootPathName' : LPCWSTR
})
def hook_GetDriveTypeW(ql: Qiling, address: int, params):
    path = params["lpRootPathName"]

    if path == 0:
        raise QlErrorNotImplemented("API not implemented")

    if path == ql.os.profile["PATH"]["systemdrive"]:
        return DRIVE_FIXED

    # TODO add configuration for drives

    return DRIVE_NO_ROOT_DIR

# BOOL GetDiskFreeSpaceW(
#   LPCWSTR lpRootPathName,
#   LPDWORD lpSectorsPerCluster,
#   LPDWORD lpBytesPerSector,
#   LPDWORD lpNumberOfFreeClusters,
#   LPDWORD lpTotalNumberOfClusters
# );
@winsdkapi(cc=STDCALL, params={
    'lpRootPathName'          : LPCWSTR,
    'lpSectorsPerCluster'     : LPDWORD,
    'lpBytesPerSector'        : LPDWORD,
    'lpNumberOfFreeClusters'  : LPDWORD,
    'lpTotalNumberOfClusters' : LPDWORD
})
def hook_GetDiskFreeSpaceW(ql: Qiling, address: int, params):
    path = params["lpRootPathName"]

    if path == ql.os.profile["PATH"]["systemdrive"]:
        pt_sectors     = params["lpSectorsPerCluster"]
        pt_bytes       = params["lpBytesPerSector"]
        pt_free_clust  = params["lpNumberOfFreeClusters"]
        pt_total_clust = params["lpTotalNumberOfClusters"]

        sectors     = ql.pack32(ql.os.profile.getint("VOLUME", "sectors_per_cluster"))
        bytes       = ql.pack32(ql.os.profile.getint("VOLUME", "bytes_per_sector"))
        free_clust  = ql.pack32(ql.os.profile.getint("VOLUME", "number_of_free_clusters"))
        total_clust = ql.pack32(ql.os.profile.getint("VOLUME", "number_of_clusters"))

        ql.mem.write(pt_sectors, sectors)
        ql.mem.write(pt_bytes, bytes)
        ql.mem.write(pt_free_clust, free_clust)
        ql.mem.write(pt_total_clust, total_clust)
    else:
        raise QlErrorNotImplemented("API not implemented")

    return 0

# BOOL CreateDirectoryA(
#  LPCSTR                lpPathName,
#  LPSECURITY_ATTRIBUTES lpSecurityAttributes
# );
@winsdkapi(cc=STDCALL, params={
    'lpPathName'           : LPCSTR,
    'lpSecurityAttributes' : LPSECURITY_ATTRIBUTES
})
def hook_CreateDirectoryA(ql: Qiling, address: int, params):
    path_name = params["lpPathName"]
    target_dir = os.path.join(ql.rootfs, path_name.replace("\\", os.sep))
    ql.log.info('TARGET_DIR = %s' % target_dir)

    # Verify the directory is in ql.rootfs to ensure no path traversal has taken place
    real_path = ql.os.path.transform_to_real_path(path_name)

    if os.path.exists(real_path):
        ql.os.last_error = ERROR_ALREADY_EXISTS
        return 0

    os.mkdir(real_path)
    return 1

# DWORD GetFileSize(
#  HANDLE  hFile,
#  LPDWORD lpFileSizeHigh
# );
@winsdkapi(cc=STDCALL, params={
    'hFile'          : HANDLE,
    'lpFileSizeHigh' : LPDWORD
})
def hook_GetFileSize(ql: Qiling, address: int, params):
    try:
        handle = ql.os.handle_manager.get(params['hFile'])

        return os.path.getsize(handle.obj.name)
    except:
        ql.os.last_error = ERROR_INVALID_HANDLE
        return 0xFFFFFFFF #INVALID_FILE_SIZE

def _CreateFileMapping(ql: Qiling, address: int, params):
    hFile = params['hFile']
    lpName = params['lpName']

    new_handle = Handle(obj=hFile, name=lpName)
    ql.os.handle_manager.append(new_handle)

    return new_handle.id

# HANDLE CreateFileMappingA(
#   HANDLE                hFile,
#   LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
#   DWORD                 flProtect,
#   DWORD                 dwMaximumSizeHigh,
#   DWORD                 dwMaximumSizeLow,
#   LPCSTR                lpName
# );
@winsdkapi(cc=STDCALL, params={
    'hFile'                   : HANDLE,
    'lpFileMappingAttributes' : LPSECURITY_ATTRIBUTES,
    'flProtect'               : DWORD,
    'dwMaximumSizeHigh'       : DWORD,
    'dwMaximumSizeLow'        : DWORD,
    'lpName'                  : LPCSTR
})
def hook_CreateFileMappingA(ql: Qiling, address: int, params):
    return _CreateFileMapping(ql, address, params)

# HANDLE CreateFileMappingW(
#   HANDLE                hFile,
#   LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
#   DWORD                 flProtect,
#   DWORD                 dwMaximumSizeHigh,
#   DWORD                 dwMaximumSizeLow,
#   LPCWSTR               lpName
# );
@winsdkapi(cc=STDCALL, params={
    'hFile'                   : HANDLE,
    'lpFileMappingAttributes' : LPSECURITY_ATTRIBUTES,
    'flProtect'               : DWORD,
    'dwMaximumSizeHigh'       : DWORD,
    'dwMaximumSizeLow'        : DWORD,
    'lpName'                  : LPCWSTR
})
def hook_CreateFileMappingW(ql: Qiling, address: int, params):
    return _CreateFileMapping(ql, address, params)

# LPVOID MapViewOfFile(
#   HANDLE hFileMappingObject,
#   DWORD  dwDesiredAccess,
#   DWORD  dwFileOffsetHigh,
#   DWORD  dwFileOffsetLow,
#   SIZE_T dwNumberOfBytesToMap
# );
@winsdkapi(cc=STDCALL, params={
    'hFileMappingObject'   : HANDLE,
    'dwDesiredAccess'      : DWORD,
    'dwFileOffsetHigh'     : DWORD,
    'dwFileOffsetLow'      : DWORD,
    'dwNumberOfBytesToMap' : SIZE_T
})
def hook_MapViewOfFile(ql: Qiling, address: int, params):
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
@winsdkapi(cc=STDCALL, params={
    'lpBaseAddress' : LPCVOID
})
def hook_UnmapViewOfFile(ql: Qiling, address: int, params):
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
@winsdkapi(cc=STDCALL, params={
    'lpExistingFileName' : LPCSTR,
    'lpNewFileName'      : LPCSTR,
    'bFailIfExists'      : BOOL
})
def hook_CopyFileA(ql: Qiling, address: int, params):
    lpExistingFileName = ql.os.path.transform_to_real_path(params["lpExistingFileName"])
    lpNewFileName = ql.os.path.transform_to_real_path(params["lpNewFileName"])
    bFailIfExists = params["bFailIfExists"]

    if bFailIfExists and os.path.exists(lpNewFileName):
        return 0

    copyfile(lpExistingFileName, lpNewFileName)
    return 1

# BOOL SetFileAttributesA(
#   LPCSTR lpFileName,
#   DWORD  dwFileAttributes
# );
@winsdkapi(cc=STDCALL, params={
    'lpFileName'       : LPCSTR,
    'dwFileAttributes' : DWORD
})
def hook_SetFileAttributesA(ql: Qiling, address: int, params):
    return 1

@winsdkapi(cc=STDCALL, params={
    'lpFileName'       : LPCWSTR,
    'dwFileAttributes' : DWORD
})
def hook_SetFileAttributesW(ql: Qiling, address: int, params):
    return 1
