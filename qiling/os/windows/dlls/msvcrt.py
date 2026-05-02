#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import time
from typing import Sequence

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.const import *
from qiling.os.windows.handle import Handle

# void __set_app_type (
#    int at
# )
@winsdkapi(cc=CDECL, params={
    'at' : INT
})
def hook___set_app_type(ql: Qiling, address: int, params):
    pass

def __alloc_strings_array(ql: Qiling, items: Sequence[str], *, wide: bool) -> int:
    '''Allocate and populate an array of strings and return its address.
    '''

    enc = 'utf-16le' if wide else 'utf-8'

    nitems = len(items)

    # allocate room for pointers to items and a trailing null pointer
    p_array = ql.os.heap.alloc((nitems + 1) * ql.arch.pointersize)

    # encode all arguments into bytes
    items_bytes = [f'{item}\x00'.encode(enc) for item in items]

    # allocate room for the items
    p_items_bytes = ql.os.heap.alloc(sum(len(a) for a in items_bytes))

    for i, item in enumerate(items_bytes):
        # write argument data
        ql.mem.write(p_items_bytes, item)

        # write pointer to argument data into the argv array
        ql.mem.write_ptr(p_array + (i * ql.arch.pointersize), p_items_bytes)

        p_items_bytes += len(item)

    # write trailing null pointer
    ql.mem.write_ptr(p_array + (nitems * ql.arch.pointersize), 0)

    return p_array

def __getmainargs(ql: Qiling, params, wide: bool) -> int:
    argc = len(ql.argv)
    argv = __alloc_strings_array(ql, ql.argv, wide=wide)
    env = __alloc_strings_array(ql, [f'{k}={v}' for k, v in ql.env], wide=wide)

    # write out paramters
    ql.mem.write_ptr(params['_Argc'], argc, 4)
    ql.mem.write_ptr(params['_Argv'], argv)
    ql.mem.write_ptr(params['_Env'], env)

    return 0

# int __getmainargs(
#    int * _Argc,
#    char *** _Argv,
#    char *** _Env,
#    int _DoWildCard,
#    _startupinfo * _StartInfo
# );
@winsdkapi(cc=CDECL, params={
    '_Argc'       : POINTER,
    '_Argv'       : POINTER,
    '_Env'        : POINTER,
    '_DoWildCard' : INT,
    '_StartInfo'  : POINTER
})
def hook___getmainargs(ql: Qiling, address: int, params):
    return __getmainargs(ql, params, wide=False)

@winsdkapi(cc=CDECL, params={
    '_Argc'       : POINTER,
    '_Argv'       : POINTER,
    '_Env'        : POINTER,
    '_DoWildCard' : INT,
    '_StartInfo'  : POINTER
})
def hook___wgetmainargs(ql: Qiling, address: int, params):
    return __getmainargs(ql, params, wide=True)

# int* __p__fmode();
@winsdkapi(cc=CDECL, params={})
def hook___p__fmode(ql: Qiling, address: int, params):
    addr = ql.os.heap.alloc(ql.arch.pointersize)
    return addr

# int* __p__commode();
@winsdkapi(cc=CDECL, params={})
def hook___p__commode(ql: Qiling, address: int, params):
    addr = ql.os.heap.alloc(ql.arch.pointersize)
    return addr

# char** __p__acmdln();
@winsdkapi(cc=CDECL, params={})
def hook___p__acmdln(ql: Qiling, address: int, params):
    # TODO: use values calculated at __getmainargs
    addr = ql.loader.import_address_table['msvcrt.dll'][b'_acmdln']
    return addr

# wchar_t ** __p__wcmdln();
@winsdkapi(cc=CDECL, params={})
def hook___p__wcmdln(ql: Qiling, address: int, params):
    # TODO: use values calculated at __getmainargs
    addr = ql.loader.import_address_table['msvcrt.dll'][b'_wcmdln']
    return addr

# unsigned int _controlfp(
#    unsigned int new,
#    unsigned int mask
# );
@winsdkapi(cc=CDECL, params={
    'new'  : UINT,
    'mask' : UINT
})
def hook__controlfp(ql: Qiling, address: int, params):
    ret = 0x8001f
    return ret

# int atexit(
#    void (__cdecl *func)(void)
# );
@winsdkapi(cc=CDECL, params={
    'func' : POINTER
}, passthru=True)
def hook_atexit(ql: Qiling, address: int, params):
    return

# char*** __p__environ(void)
@winsdkapi(cc=CDECL, params={})
def hook___p__environ(ql: Qiling, address: int, params):
    ret = ql.os.heap.alloc(ql.arch.pointersize * len(ql.os.env))

    for i, (k, v) in enumerate(ql.os.env.items()):
        entry = bytes(f'{k}={v}', 'ascii') + b'\x00'
        p_entry = ql.os.heap.alloc(len(entry))
        ql.mem.write(p_entry, entry)

        pp_entry = ql.os.heap.alloc(ql.arch.pointersize)
        ql.mem.write_ptr(pp_entry, p_entry)
        ql.mem.write_ptr(ret + i * ql.arch.pointersize, pp_entry)

    return ret

# int puts(
#    const char *str
# );
@winsdkapi(cc=CDECL, params={
    'str' : STRING
})
def hook_puts(ql: Qiling, address: int, params):
    s = params["str"] + '\n'

    ql.os.stdout.write(s.encode("utf-8"))

    return len(s)

# void _cexit( void );
@winsdkapi(cc=CDECL, params={})
def hook__cexit(ql: Qiling, address: int, params):
    pass

# void exit(
#    int const status
# );
@winsdkapi(cc=CDECL, params={
    'status' : INT
})
def hook_exit(ql: Qiling, address: int, params):
    ql.emu_stop()

# char***    __cdecl __p___argv (void);
@winsdkapi(cc=CDECL, params={})
def hook___p___argv(ql: Qiling, address: int, params):
    # allocate argv pointers array
    p_argv = ql.os.heap.alloc(ql.arch.pointersize * len(ql.os.argv))

    for i, each in enumerate(ql.os.argv):
        entry = bytes(each, 'ascii') + b'\x00'
        p_entry = ql.os.heap.alloc(len(entry))

        ql.mem.write(p_entry, entry)
        ql.mem.write_ptr(p_argv + i * ql.arch.pointersize, p_entry)

    ret = ql.os.heap.alloc(ql.arch.pointersize)
    ql.mem.write_ptr(ret, p_argv)

    return ret

# int* __p___argc(void)
@winsdkapi(cc=CDECL, params={})
def hook___p___argc(ql: Qiling, address: int, params):
    ret = ql.os.heap.alloc(ql.arch.pointersize)

    ql.mem.write_ptr(ret, len(ql.argv))

    return ret

# TODO: this one belongs to ucrtbase.dll
@winsdkapi(cc=CDECL, params={}, passthru=True)
def hook__get_initial_narrow_environment(ql: Qiling, address: int, params):
    # If the native version of this function does not
    # get to run, then debug versions of the CRT DLLs can fail
    # their initialization.
    return

# int sprintf ( char * str, const char * format, ... );
@winsdkapi(cc=CDECL, params={
    'buff'   : POINTER,
    'format' : STRING,
    'arglist': POINTER
})
def hook_sprintf(ql: Qiling, address: int, params):
    buff = params['buff']
    format = params['format']
    arglist = params['arglist']

    if format == 0:
        format = "(null)"

    args = ql.os.utils.va_list(arglist)

    count, upd_args = ql.os.utils.sprintf(buff, format, args, wstring=False)
    upd_args(params)

    return count

# int printf(const char *format, ...)
@winsdkapi(cc=CDECL, params={
    'format': STRING
})
def hook_printf(ql: Qiling, address: int, params):
    format = params['format']

    if format == 0:
        format = "(null)"

    args = ql.os.fcall.readEllipsis(params.values())

    count, upd_args = ql.os.utils.printf(format, args, wstring=False)
    upd_args(params)

    return count

# int wprintf(const wchar_t *format, ...)
@winsdkapi(cc=CDECL, params={
    'format': WSTRING
})
def hook_wprintf(ql: Qiling, address: int, params):
    format = params['format']

    if format == 0:
        format = "(null)"

    args = ql.os.fcall.readEllipsis(params.values())

    count, upd_args = ql.os.utils.printf(format, args, wstring=True)
    upd_args(params)

    return count

def __stdio_common_vfprintf(ql: Qiling, address: int, params, wstring: bool):
    format = params['_Format']
    arglist = params['_ArgList']

    # TODO: take _Stream into account

    args = ql.os.utils.va_list(arglist)

    count, upd_args = ql.os.utils.printf(format, args, wstring)
    upd_args(params)

    return count

@winsdkapi(cc=CDECL, params={
    '_Options' : PARAM_INT64,
    '_Stream'  : POINTER,
    '_Format'  : STRING,
    '_Locale'  : DWORD,
    '_ArgList' : POINTER
})
def hook___stdio_common_vfprintf(ql: Qiling, address: int, params):
    return __stdio_common_vfprintf(ql, address, params, False)

@winsdkapi(cc=CDECL, params={
    '_Options' : PARAM_INT64,
    '_Stream'  : POINTER,
    '_Format'  : WSTRING,
    '_Locale'  : DWORD,
    '_ArgList' : POINTER
})
def hook___stdio_common_vfwprintf(ql: Qiling, address: int, params):
    return __stdio_common_vfprintf(ql, address, params, True)

def __stdio_common_vsprintf(ql: Qiling, address: int, params, wstring: bool):
    buff = params['_Buffer']
    format = params['_Format']
    arglist = params['_ArgList']

    # TODO: take _BufferCount into account

    args = ql.os.utils.va_list(arglist)

    count, upd_args = ql.os.utils.sprintf(buff, format, args, wstring)
    upd_args(params)

    return count

@winsdkapi(cc=CDECL, params={
    '_Options'     : PARAM_INT64,
    '_Buffer'      : POINTER,
    '_BufferCount' : SIZE_T,
    '_Format'      : STRING,
    '_Locale'      : DWORD,
    '_ArgList'     : POINTER
})
def hook___stdio_common_vsprintf(ql: Qiling, address: int, params):
    return __stdio_common_vsprintf(ql, address, params, False)

@winsdkapi(cc=CDECL, params={
    '_Options'     : PARAM_INT64,
    '_Buffer'      : POINTER,
    '_BufferCount' : SIZE_T,
    '_MaxCount'    : SIZE_T,
    '_Format'      : STRING,
    '_Locale'      : DWORD,
    '_ArgList'     : POINTER
})
def hook___stdio_common_vsnprintf(ql: Qiling, address: int, params):
    return __stdio_common_vsprintf(ql, address, params, False)

@winsdkapi(cc=CDECL, params={
    '_Options'     : PARAM_INT64,
    '_Buffer'      : POINTER,
    '_BufferCount' : SIZE_T,
    '_Format'      : WSTRING,
    '_Locale'      : DWORD,
    '_ArgList'     : POINTER
})
def hook___stdio_common_vswprintf(ql: Qiling, address: int, params):
    return __stdio_common_vsprintf(ql, address, params, True)

@winsdkapi(cc=CDECL, params={
    '_Options'     : PARAM_INT64,
    '_Buffer'      : POINTER,
    '_BufferCount' : SIZE_T,
    '_MaxCount'    : SIZE_T,
    '_Format'      : WSTRING,
    '_Locale'      : DWORD,
    '_ArgList'     : POINTER
})
def hook___stdio_common_vsnwprintf(ql: Qiling, address: int, params):
    return __stdio_common_vsprintf(ql, address, params, True)

# all the "_s" versions are aliases to their non-"_s" counterparts

@winsdkapi(cc=CDECL, params={
    '_Options' : PARAM_INT64,
    '_Stream'  : POINTER,
    '_Format'  : STRING,
    '_Locale'  : DWORD,
    '_ArgList' : POINTER
})
def hook___stdio_common_vfprintf_s(ql: Qiling, address: int, params):
    return hook___stdio_common_vfprintf.__wrapped__(ql, address, params)

@winsdkapi(cc=CDECL, params={
    '_Options' : PARAM_INT64,
    '_Stream'  : POINTER,
    '_Format'  : WSTRING,
    '_Locale'  : DWORD,
    '_ArgList' : POINTER
})
def hook___stdio_common_vfwprintf_s(ql: Qiling, address: int, params):
    return hook___stdio_common_vfwprintf.__wrapped__(ql, address, params)

@winsdkapi(cc=CDECL, params={
    '_Options'     : PARAM_INT64,
    '_Buffer'      : POINTER,
    '_BufferCount' : SIZE_T,
    '_Format'      : STRING,
    '_Locale'      : DWORD,
    '_ArgList'     : POINTER
})
def hook___stdio_common_vsprintf_s(ql: Qiling, address: int, params):
    return hook___stdio_common_vsprintf.__wrapped__(ql, address, params)

@winsdkapi(cc=CDECL, params={
    '_Options'     : PARAM_INT64,
    '_Buffer'      : POINTER,
    '_BufferCount' : SIZE_T,
    '_MaxCount'    : SIZE_T,
    '_Format'      : STRING,
    '_Locale'      : DWORD,
    '_ArgList'     : POINTER
})
def hook___stdio_common_vsnprintf_s(ql: Qiling, address: int, params):
    return hook___stdio_common_vsnprintf.__wrapped__(ql, address, params)

@winsdkapi(cc=CDECL, params={
    '_Options'     : PARAM_INT64,
    '_Buffer'      : POINTER,
    '_BufferCount' : SIZE_T,
    '_Format'      : WSTRING,
    '_Locale'      : DWORD,
    '_ArgList'     : POINTER
})
def hook___stdio_common_vswprintf_s(ql: Qiling, address: int, params):
    return hook___stdio_common_vswprintf.__wrapped__(ql, address, params)

@winsdkapi(cc=CDECL, params={
    '_Options'     : PARAM_INT64,
    '_Buffer'      : POINTER,
    '_BufferCount' : SIZE_T,
    '_MaxCount'    : SIZE_T,
    '_Format'      : WSTRING,
    '_Locale'      : DWORD,
    '_ArgList'     : POINTER
})
def hook___stdio_common_vsnwprintf_s(ql: Qiling, address: int, params):
    return hook___stdio_common_vsnwprintf.__wrapped__(ql, address, params)

@winsdkapi(cc=CDECL, params={})
def hook___lconv_init(ql: Qiling, address: int, params):
    return 0

@winsdkapi(cc=CDECL, params={
    'str'     : POINTER,
    'maxsize' : SIZE_T
})
def hook___strncnt(ql: Qiling, address: int, params):
    s = params["str"]
    maxsize = params["maxsize"]

    data = ql.mem.read(s, maxsize)

    # a simple hack to make sure a null terminator is found at most at 'maxsize'
    return (data + b'\x00').find(b'\00')

# size_t strlen(
#    const char *str
# );
@winsdkapi(cc=CDECL, params={
    'str' : STRING
})
def hook_strlen(ql: Qiling, address: int, params):
    s = params["str"]

    return 0 if not s else len(s)

# int strncmp(
#    const char *string1,
#    const char *string2,
#    size_t count
# );
@winsdkapi(cc=CDECL, params={
    'string1' : STRING,
    'string2' : STRING,
    'count'   : SIZE_T
})
def hook_strncmp(ql: Qiling, address: int, params):
    s1 = params["string1"]
    s2 = params["string2"]
    count = params["count"]

    string1 = s1[:count]
    string2 = s2[:count]

    if string1 == string2:
        result = 0
    elif string1 > string2:
        result = 1
    else:
        result = -1

    return result

@winsdkapi(cc=CDECL, params={
    'size' : UINT
}, passthru=True)
def hook__malloc_base(ql: Qiling, address: int, params):
    return

# void* malloc（unsigned int size)
@winsdkapi(cc=CDECL, params={
    'size' : UINT
}, passthru=True)
def hook_malloc(ql: Qiling, address: int, params):
    return

# void* __cdecl _realloc_base(
#     void*  const block,
#     size_t const size
#     )
@winsdkapi(cc=CDECL, params={
    'block' : POINTER,
    'size' : UINT
}, passthru=True)
def hook__realloc_base(ql: Qiling, address: int, params):
    return

@winsdkapi(cc=CDECL, params={
    'address': POINTER
}, passthru=True)
def hook__free_base(ql: Qiling, address: int, params):
    return

# void* free（void *address)
@winsdkapi(cc=CDECL, params={
    'address': POINTER
}, passthru=True)
def hook_free(ql: Qiling, address: int, params):
    return

# _onexit_t _onexit(
#    _onexit_t function
# );
@winsdkapi(cc=CDECL, params={
    'function' : POINTER
})
def hook__onexit(ql: Qiling, address: int, params):
    function = params['function']

    addr = ql.os.heap.alloc(ql.arch.pointersize)
    ql.mem.write_ptr(addr, function)

    return addr

# _onexit_t __dllonexit(
#    _onexit_t func,
#    _PVFV **  pbegin,
#    _PVFV **  pend
#    );
@winsdkapi(cc=STDCALL, params={
    'function': POINTER,
    'pbegin': POINTER,
    'pend': POINTER
})
def hook___dllonexit(ql: Qiling, address: int, params):
    function = params['function']

    if function:
        addr = ql.os.heap.alloc(ql.arch.pointersize)
        ql.mem.write_ptr(addr, function)

        return addr
    
    return 0

# void *memset(
#    void *dest,
#    int c,
#    size_t count
# );
@winsdkapi(cc=CDECL, params={
    'dest'  : POINTER,
    'c'     : INT,
    'count' : SIZE_T
}, passthru=True)
def hook_memset(ql: Qiling, address: int, params):
    return

@winsdkapi(cc=CDECL, params={
    'num'  : SIZE_T,
    'size' : SIZE_T
}, passthru=True)
def hook__calloc_base(ql: Qiling, address: int, params):
    return

# void *calloc(
#    size_t num,
#    size_t size
# );
@winsdkapi(cc=CDECL, params={
    'num'  : SIZE_T,
    'size' : SIZE_T
}, passthru=True)
def hook_calloc(ql: Qiling, address: int, params):
    return

# void * memmove(
#   void *dest,
#   const void *src,
#   size_t num
# );
@winsdkapi(cc=CDECL, params={
    'dest' : POINTER,
    'src'  : POINTER,
    'num'  : SIZE_T
}, passthru=True)
def hook_memmove(ql: Qiling, address: int, params):
    return

# int _ismbblead(
#    unsigned int c
# );
@winsdkapi(cc=CDECL, params={
    'c' : UINT
})
def hook__ismbblead(ql: Qiling, address: int, params):
    # TODO check if is CDECL or not
    # If locale is utf-8 always return 0
    loc = LOCALE["default"]

    if loc[0x1004] == "utf-8":
        return 0

    raise QlErrorNotImplemented("API not implemented")

# errno_t _wfopen_s(
#    FILE** pFile,
#    const wchar_t *filename,
#    const wchar_t *mode
# );
@winsdkapi(cc=CDECL, params={
    'pFile'    : POINTER,
    'filename' : WSTRING,
    'mode'     : WSTRING
})
def hook__wfopen_s(ql: Qiling, address: int, params):
    pFile = params["pFile"]
    filename = params["filename"]
    mode = params["mode"]

    f = ql.os.fs_mapper.open(filename, mode)
    new_handle = Handle(obj=f)
    ql.os.handle_manager.append(new_handle)
    ql.mem.write_ptr(pFile, new_handle.id)

    return 1

# time_t time( time_t *destTime );
@winsdkapi(cc=CDECL, params={
    'destTime' : POINTER
})
def hook__time64(ql: Qiling, address: int, params):
    dst = params["destTime"]

    time_wasted = int(time.time())

    if dst:
        ql.mem.write_ptr(dst, time_wasted, 8)

    return time_wasted

# void abort( void );
@winsdkapi(cc=CDECL, params={})
def hook_abort(ql: Qiling, address: int, params):
    # During testing, it was found that programs terminating abnormally
    # via abort() terminated with exit code=STATUS_STACK_BUFFER_OVERRUN.
    # According to Microsoft's devblog, this does not necessarily mean
    # that a stack buffer overrun occurred.
    # Rather, it can indicate abnormal program termination in a variety of
    # situations, including abort().
    # https://devblogs.microsoft.com/oldnewthing/20190108-00/?p=100655
    # 
    ql.os.exit_code = STATUS_STACK_BUFFER_OVERRUN

    ql.emu_stop()