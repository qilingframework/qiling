#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ntpath
import os

from shutil import copyfile
from datetime import datetime

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.handle import Handle
from qiling.os.windows.structs import FILETIME, make_win32_find_data

# DWORD GetFileType(
#   HANDLE hFile
# );
@winsdkapi(cc=STDCALL, params={
    'hFile' : HANDLE
})
def hook_GetFileType(ql: Qiling, address: int, params):
    hFile = params["hFile"]

    handle = ql.os.handle_manager.get(hFile)

    if handle is None:
        raise QlErrorNotImplemented("API not implemented")

    # technically is not always a type_char but.. almost
    return FILE_TYPE_CHAR

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

    if not filename:
        return INVALID_HANDLE_VALUE

    if len(filename) >= MAX_PATH:
        return ERROR_INVALID_PARAMETER

    # Check if path exists
    filesize = 0

    try:
        f = ql.os.fs_mapper.open(filename, "r")

        filesize = os.path.getsize(f.name)
    except FileNotFoundError:
        ql.os.last_error = ERROR_FILE_NOT_FOUND

        return INVALID_HANDLE_VALUE

    # Create a handle for the path
    new_handle = Handle(obj=f)
    ql.os.handle_manager.append(new_handle)

    # calculate file time
    epoch = datetime(1601, 1, 1)
    elapsed = datetime.now() - epoch

    # number of 100-nanosecond intervals since Jan 1, 1601 utc
    # where: (10 ** 9) / 100 -> (10 ** 7)
    hnano = int(elapsed.total_seconds() * (10 ** 7))

    mask = (1 << 32) - 1

    ftime = FILETIME(
        (hnano >>  0) & mask,
        (hnano >> 32) & mask
    )

    fdata_struct = make_win32_find_data(ql.arch.bits, wide=False)

    with fdata_struct.ref(ql.mem, pointer) as fdata_obj:
        fdata_obj.dwFileAttributes   = FILE_ATTRIBUTE_NORMAL
        fdata_obj.ftCreationTime     = ftime
        fdata_obj.ftLastAccessTime   = ftime
        fdata_obj.ftLastWriteTime    = ftime
        fdata_obj.nFileSizeHigh      = (filesize >> 32) & mask
        fdata_obj.nFileSizeLow       = (filesize >>  0) & mask
        fdata_obj.dwReserved0        = 0
        fdata_obj.dwReserved1        = 0
        fdata_obj.cFileName          = filename
        fdata_obj.cAlternateFileName = 0
        fdata_obj.dwFileType         = 0
        fdata_obj.dwCreatorType      = 0
        fdata_obj.wFinderFlags       = 0

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

    handle = ql.os.handle_manager.get(hFile)

    if handle is None:
        ql.os.last_error = ERROR_INVALID_HANDLE
        return 0

    data = handle.obj.read(nNumberOfBytesToRead)

    ql.mem.write(lpBuffer, data)
    ql.mem.write_ptr(lpNumberOfBytesRead, len(data), 4)

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

    handle = ql.os.handle_manager.get(hFile)

    if handle is None:
        ql.os.last_error = ERROR_INVALID_HANDLE
        return 0

    data = ql.mem.read(lpBuffer, nNumberOfBytesToWrite)

    if hFile in (STD_OUTPUT_HANDLE, STD_ERROR_HANDLE):
        ql.os.stats.log_string(data.decode())

    written = handle.obj.write(bytes(data))
    ql.mem.write_ptr(lpNumberOfBytesWritten, written, 4)

    return 1

def _CreateFile(ql: Qiling, address: int, params):
    s_lpFileName = params["lpFileName"]
    dwDesiredAccess = params["dwDesiredAccess"]
    # dwShareMode = params["dwShareMode"]
    # lpSecurityAttributes = params["lpSecurityAttributes"]
    
    # Handle Creation Disposition. I.e. how to respond
    # when a file either exists or doesn't
    # See https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
    dwCreationDisposition = params["dwCreationDisposition"]

    # dwFlagsAndAttributes = params["dwFlagsAndAttributes"]
    # hTemplateFile = params["hTemplateFile"]

    # access mask DesiredAccess
    perm_write = dwDesiredAccess & GENERIC_WRITE
    perm_read  = dwDesiredAccess & GENERIC_READ
    
    # TODO: unused
    perm_exec = dwDesiredAccess & GENERIC_EXECUTE

    # only open file if it exists. error otherwise
    open_existing = (
        (dwCreationDisposition == OPEN_EXISTING) or
        (dwCreationDisposition == TRUNCATE_EXISTING ) 
        )
     
    # check if the file exists 
    # TODO: race condition if file is deleted/reated  
    file_exists = ql.os.fs_mapper.file_exists(s_lpFileName)

    if (open_existing and (not file_exists)):
        # the CreationDisposition wants a file to exist
        # it does not 
        ql.os.last_error = ERROR_FILE_NOT_FOUND
        return INVALID_HANDLE_VALUE

    if ((dwCreationDisposition == CREATE_NEW ) and file_exists):
        # only create a file if it does not exist. 
        # if it does, error
        ql.os.last_error = ERROR_FILE_EXISTS

    truncate  = (dwCreationDisposition == CREATE_ALWAYS) or  (dwCreationDisposition == TRUNCATE_EXISTING)

    # TODO: this function does not handle general access masks. 
    # see https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask
    # it is only able to handle Generic R/W

    # read only 
    if (perm_read) and ( not (perm_write)):
        mode = "rb"

    # Write only
    elif ( perm_write and (not perm_read)):
        # TODO: fopen modes do not allow for write only access
        # Likely need to use os.open instead. 

        if (truncate and (not open_existing)) or (truncate and open_existing and file_exists):
            # create a new file or truncate an existing one
            mode = "wb"
        else:   
            ql.log.warn("_CreateFile has been called with Write only access. This is not currently supported and the handle is still allows for read access!")
            # read/write, do not create. do not truncatd
            mode = "rb+"
    
    elif perm_read and perm_write:
        # Note that this ignores exec access mask 
        mode = "rb+"

    elif perm_exec:
        # TODO: handle exec access mask
        # it is only executable or has a non standard access mask
        ql.log.warn("_CreateFile has been called with executable only access or with a non standard access mask. This is not currently supported and the handle is set to Read/Write")
        mode = "rb+"        
    else:
        # This is probably an invalid access mask
        ql.log.warn(f"Invalid access mask provided: {dwDesiredAccess}")
        # TODO: add error code 
        return INVALID_HANDLE_VALUE

    try:
        # we should have exited by now if the file doesn't exist
        if (not file_exists) and (mode != "wb"):
            status = ql.os.fs_mapper.create_empty_file(s_lpFileName)
            if not status:
                # could not create a new file
                # bail out.
                # TODO: set last_error
                ql.log.warn(f"_CreateFile could not create new file {s_lpFileName}")
                return INVALID_HANDLE_VALUE    

        f = ql.os.fs_mapper.open(s_lpFileName, mode)
        if truncate and mode != "wb":
            # redundant if mode is wb
            f.truncate(0)

        if dwCreationDisposition == CREATE_ALWAYS:
                # we overwrote the file.
                ql.os.last_error = ERROR_ALREADY_EXISTS
                
        if dwCreationDisposition == OPEN_ALWAYS:
            ql.os.last_error = ERROR_ALREADY_EXISTS
            
    except FileNotFoundError:
        # Creation disposition determines what happens when the file doesn't exist
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

def _GetTempPath(ql: Qiling, address: int, params, *, wide: bool):
    vtmpdir = ntpath.join(ql.os.windir, 'Temp')
    htmpdir = ql.os.path.virtual_to_host_path(vtmpdir)

    if ql.os.path.is_safe_host_path(htmpdir):
        if not os.path.exists(htmpdir):
            os.makedirs(htmpdir, 0o755)

    nBufferLength = params['nBufferLength']
    lpBuffer = params['lpBuffer']

    enc = 'utf-16le' if wide else 'utf-8'

    # temp dir path has to end with a path separator
    tmpdir = f'{vtmpdir}{ntpath.sep}'.encode(enc)
    cstr = tmpdir + '\x00'.encode(enc)

    if nBufferLength >= len(cstr):
        ql.mem.write(lpBuffer, cstr)

    # returned length does not include the null-terminator
    return len(tmpdir)

# DWORD GetTempPathW(
#   DWORD  nBufferLength,
#   LPWSTR lpBuffer
# );
@winsdkapi(cc=STDCALL, params={
    'nBufferLength' : DWORD,
    'lpBuffer'      : LPWSTR
})
def hook_GetTempPathW(ql: Qiling, address: int, params):
    return _GetTempPath(ql, address, params, wide=True)

# DWORD GetTempPathA(
#   DWORD  nBufferLength,
#   LPSTR lpBuffer
# );
@winsdkapi(cc=STDCALL, params={
    'nBufferLength' : DWORD,
    'lpBuffer'      : LPSTR
})
def hook_GetTempPathA(ql: Qiling, address: int, params):
    return _GetTempPath(ql, address, params, wide=False)

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
    lpszLongPath = params['lpszLongPath']
    lpszShortPath = params['lpszShortPath']
    cchBuffer = params['cchBuffer']

    def __shorten(p: str) -> str:
        name, ext = ntpath.splitext(p)

        return f'{(name[:6] + "~1") if len(name) > 8 else name}{ext}'

    shortpath = ntpath.join(*(__shorten(elem) for elem in lpszLongPath.split(ntpath.sep)))
    encoded = f'{shortpath}\x00'.encode('utf-16le')

    if len(shortpath) > cchBuffer:
        return len(shortpath) + 1

    if lpszShortPath:
        ql.mem.write(lpszShortPath, encoded)

    # on succes, return chars count excluding null-term
    return len(shortpath)


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
        ql.mem.write_ptr(lpMaximumComponentLength, 255, 2)

    pt_serial_number = params["lpVolumeSerialNumber"]
    if pt_serial_number != 0:
        # TODO maybe has to be int
        serial_number = (ql.os.profile["VOLUME"]["serial_number"] + "\x00").encode("utf-16le")
        ql.mem.write(pt_serial_number, serial_number)

    pt_system_type = params["lpFileSystemNameBuffer"]
    pt_flag = params["lpFileSystemFlags"]

    if pt_flag != 0:
        # TODO implement
        ql.mem.write_ptr(pt_flag, 0x00020000, 4)

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
    lpPathName = params['lpPathName']

    dst = ql.os.path.virtual_to_host_path(lpPathName)

    if not ql.os.path.is_safe_host_path(dst):
        ql.os.last_error = ERROR_GEN_FAILURE
        return 0

    if os.path.exists(dst):
        ql.os.last_error = ERROR_ALREADY_EXISTS
        return 0

    os.mkdir(dst, 0o755)

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
    hFile = params["hFile"]

    handle = ql.os.handle_manager.get(hFile)

    if handle is None:
        ql.os.last_error = ERROR_INVALID_HANDLE
        return -1 # INVALID_FILE_SIZE

    try:

        return os.path.getsize(handle.obj.name)
    except:
        ql.os.last_error = ERROR_INVALID_HANDLE
        return -1 # INVALID_FILE_SIZE

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
    lpExistingFileName = params['lpExistingFileName']
    lpNewFileName = params['lpNewFileName']
    bFailIfExists = params['bFailIfExists']

    src = ql.os.path.virtual_to_host_path(lpExistingFileName)
    dst = ql.os.path.virtual_to_host_path(lpNewFileName)

    if not ql.os.path.is_safe_host_path(src) or not ql.os.path.is_safe_host_path(dst):
        ql.os.last_error = ERROR_GEN_FAILURE
        return 0

    if bFailIfExists and os.path.exists(dst):
        ql.os.last_error = ERROR_FILE_EXISTS
        return 0

    copyfile(src, dst)

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

# BOOL AreFileApisANSI();
@winsdkapi(cc=STDCALL, params={})
def hook_AreFileApisANSI(ql: Qiling, address: int, params):
    # TODO make this coherent with SetFileApisToANSI/OEM calls
    return 1

# void SetFileApisToANSI();
@winsdkapi(cc=STDCALL, params={})
def hook_SetFileApisToANSI(ql: Qiling, address: int, params):
    pass

# void SetFileApisToOEM();
@winsdkapi(cc=STDCALL, params={})
def hook_SetFileApisToOEM(ql: Qiling, address: int, params):
    pass

def _DeleteFile(ql: Qiling, address: int, params):
    lpFileName = params["lpFileName"]

    dst = ql.os.path.virtual_to_host_path(lpFileName)

    if not ql.os.path.is_safe_host_path(dst):
        ql.os.last_error = ERROR_GEN_FAILURE
        return 0

    try:
        os.remove(dst)
    except OSError:
        return 0

    return 1

# BOOL DeleteFileA(
#   LPCSTR lpFileName
# );
@winsdkapi(cc=STDCALL, params={
    'lpFileName' : LPCSTR
})
def hook_DeleteFileA(ql: Qiling, address: int, params):
    return _DeleteFile(ql, address, params)

# BOOL DeleteFileW(
#   LPCWSTR lpFileName
# );
@winsdkapi(cc=STDCALL, params={
    'lpFileName' : LPCWSTR
})
def hook_DeleteFileW(ql: Qiling, address: int, params):
    return _DeleteFile(ql, address, params)
