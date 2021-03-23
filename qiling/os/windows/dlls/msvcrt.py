#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import time

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.const import LOCALE
from qiling.os.windows.handle import Handle

dllname = 'msvcrt_dll'

# void __set_app_type (
#    int at
# )
@winsdkapi(cc=CDECL)
def hook___set_app_type(ql: Qiling, address: int, params):
    pass


# int __getmainargs(
#     int * _Argc,
#    char *** _Argv,
#    char *** _Env,
#    int _DoWildCard,
# _startupinfo * _StartInfo);
@winsdkapi(cc=CDECL,
    replace_params={"_Argc": POINTER, "_Argv": POINTER, "_Env": POINTER, "_DoWildCard": INT, "_StartInfo": POINTER})
def hook___getmainargs(ql: Qiling, address: int, params):
    ret = 0
    return ret


# int* __p__fmode(
# );
@winsdkapi(cc=CDECL)
def hook___p__fmode(ql: Qiling, address: int, params):
    addr = ql.os.heap.alloc(ql.pointersize)
    return addr


# int * __p__commode(
#    );
@winsdkapi(cc=CDECL)
def hook___p__commode(ql: Qiling, address: int, params):
    addr = ql.os.heap.alloc(ql.pointersize)
    return addr


# char ** __p__acmdln(
#    );
@winsdkapi(cc=CDECL)
def hook___p__acmdln(ql: Qiling, address: int, params):
    addr = ql.loader.import_address_table['msvcrt.dll'][b'_acmdln']
    return addr

# wchar_t ** __p__wcmdln(
#    );
@winsdkapi(cc=CDECL)
def hook___p__wcmdln(ql: Qiling, address: int, params):
    addr = ql.loader.import_address_table['msvcrt.dll'][b'_wcmdln']
    return addr


# unsigned int _controlfp(
#    unsigned int new,
#    unsigned int mask
# );
@winsdkapi(cc=CDECL, replace_params={"new": UINT, "mask": UINT})
def hook__controlfp(ql: Qiling, address: int, params):
    ret = 0x8001f
    return ret


# int atexit(
#    void (__cdecl *func)(void)
# );
@winsdkapi(cc=CDECL, replace_params={"func": POINTER})
def hook_atexit(ql: Qiling, address: int, params):
    ret = 0
    return ret


# char*** __p__environ(void)
@winsdkapi(cc=CDECL)
def hook___p__environ(ql: Qiling, address: int, params):
    ret = ql.os.heap.alloc(ql.pointersize * len(ql.os.env))
    count = 0
    for key in ql.os.env:
        pointer = ql.os.heap.alloc(ql.pointersize)
        env = key + "=" + ql.os.env[key]
        env_addr = ql.os.heap.alloc(len(env) + 1)
        ql.mem.write(env_addr, bytes(env, 'ascii') + b'\x00')
        ql.mem.write(pointer, ql.pack(env_addr))
        ql.mem.write(ret + count * ql.pointersize, ql.pack(pointer))
        count += 1
    return ret


# int puts(
#    const char *str
# );
@winsdkapi(cc=CDECL, replace_params={"str": STRING})
def hook_puts(ql: Qiling, address: int, params):
    string = params["str"] + '\n'

    ql.os.stdout.write(string.encode("utf-8"))

    return len(string)


# void _cexit( void );
@winsdkapi(cc=CDECL)
def hook__cexit(ql: Qiling, address: int, params):
    pass


# void __cdecl _initterm(
#    PVFV *,
#    PVFV *
# );
@winsdkapi(cc=CDECL, replace_params={"pfbegin": POINTER, "pfend": POINTER})
def hook__initterm(ql: Qiling, address: int, params):
    pass


# void exit(
#    int const status
# );
@winsdkapi(cc=CDECL, replace_params={"status": INT})
def hook_exit(ql: Qiling, address: int, params):
    ql.emu_stop()
    ql.os.PE_RUN = False


# int __cdecl _initterm_e(
#    PVFV *,
#    PVFV *
# );
@winsdkapi(cc=CDECL, replace_params={"pfbegin": POINTER, "pfend": POINTER})
def hook__initterm_e(ql: Qiling, address: int, params):
    return 0


# char***    __cdecl __p___argv (void);
@winsdkapi(cc=CDECL)
def hook___p___argv(ql: Qiling, address: int, params):
    ret = ql.os.heap.alloc(ql.pointersize)
    argv_addr = ql.os.heap.alloc(ql.pointersize * len(ql.os.argv))
    count = 0
    for each in ql.os.argv:
        argv = ql.os.heap.alloc(len(each) + 1)
        ql.mem.write(argv, bytes(each, 'ascii') + b'\x00')
        ql.mem.write(argv_addr + count * ql.pointersize, ql.pack(argv))
        count += 1
    ql.mem.write(ret, ql.pack(argv_addr))
    return ret


# int* __p___argc(void)
@winsdkapi(cc=CDECL)
def hook___p___argc(ql: Qiling, address: int, params):
    ql.log.debug("_p___argc")
    ret = ql.os.heap.alloc(ql.pointersize)
    ql.mem.write(ret, ql.pack(len(ql.argv)))
    return ret


@winsdkapi(cc=CDECL)
def hook__get_initial_narrow_environment(ql: Qiling, address: int, params):
    ret = 0
    count = 0
    for key in ql.env:
        value = key + "=" + ql.env[key]
        env = ql.os.heap.alloc(len(value) + 1)
        if count == 0:
            ret = env
        ql.mem.write(env, bytes(value, 'ascii') + b'\x00')
        count += 1
    return ret

# int sprintf ( char * str, const char * format, ... );
@winsdkapi(cc=CDECL, dllname=dllname, replace_params={'buff': POINTER, 'format': STRING, 'arglist': POINTER})
def hook_sprintf(ql: Qiling, address: int, params):
    buff = params['buff']
    format = params['format']
    arglist = params['arglist']

    if format == 0:
        format = "(null)"

    args = ql.os.utils.va_list(format, arglist)
    count = ql.os.utils.sprintf(buff, format, args, wstring=False)
    ql.os.utils.update_ellipsis(params, args)

    return count


# int printf(const char *format, ...)
@winsdkapi(cc=CDECL, replace_params={'format': STRING})
def hook_printf(ql: Qiling, address: int, params):
    format = params['format']

    if format == 0:
        format = "(null)"

    nargs = format.count("%")
    ptypes = (POINTER, ) + (PARAM_INTN, ) * nargs
    args = ql.os.fcall.readParams(ptypes)[1:]

    count = ql.os.utils.printf(format, args, wstring=False)
    ql.os.utils.update_ellipsis(params, args)

    return count

# int wprintf(const wchar_t *format, ...)
@winsdkapi(cc=CDECL, replace_params={'format': WSTRING})
def hook_wprintf(ql: Qiling, address: int, params):
    format = params['format']

    if format == 0:
        format = "(null)"

    nargs = format.count("%")
    ptypes = (POINTER, ) + (PARAM_INTN, ) * nargs
    args = ql.os.fcall.readParams(ptypes)[1:]

    count = ql.os.utils.printf(format, args, wstring=True)
    ql.os.utils.update_ellipsis(params, args)

    return count

# MSVCRT_FILE * CDECL MSVCRT___acrt_iob_func(unsigned idx)
@winsdkapi(cc=CDECL, replace_params={"idx": UINT})
def hook___acrt_iob_func(ql: Qiling, address: int, params):
    ret = 0
    return ret

# __stdio_common_vfprintf(_OptionsStorage, FILE* _Stream, char const* _Format, _locale_t _Locale, va_list _ArgList)
@winsdkapi(cc=CDECL, replace_params={'optstorage': PARAM_INT64, 'stream': POINTER, 'format': STRING, 'locale': DWORD, 'arglist': POINTER})
def hook___stdio_common_vfprintf(ql: Qiling, address: int, params):
    format = params['format']
    arglist = params['arglist']

    args = ql.os.utils.va_list(format, arglist)
    count = ql.os.utils.printf(format, args, wstring=False)
    ql.os.utils.update_ellipsis(params, args)

    return count


@winsdkapi(cc=CDECL, replace_params={'optstorage': PARAM_INT64, 'stream': POINTER, 'format': WSTRING, 'locale': DWORD, 'arglist': POINTER})
def hook___stdio_common_vfwprintf(ql: Qiling, address: int, params):
    format = params['format']
    arglist = params['arglist']

    args = ql.os.utils.va_list(format, arglist)
    count = ql.os.utils.printf(format, args, wstring=True)
    ql.os.utils.update_ellipsis(params, args)

    return count

# int __cdecl __stdio_common_vswprintf_s(unsigned __int64,wchar_t*,size_t,const wchar_t*,_locale_t,__ms_va_list)
@winsdkapi(cc=CDECL, replace_params={'optstorage': PARAM_INT64, 'buff': POINTER, 'size': SIZE_T, 'format': WSTRING, 'locale': DWORD, 'arglist': POINTER})
def hook___stdio_common_vswprintf_s(ql: Qiling, address: int, params):
    buff = params['buff']
    format = params['format']
    arglist = params['arglist']

    args = ql.os.utils.va_list(format, arglist)
    count = ql.os.utils.sprintf(buff, format, args, wstring=True)
    ql.os.utils.update_ellipsis(params, args)

    return count

@winsdkapi(cc=CDECL)
def hook___lconv_init(ql: Qiling, address: int, params):
    ret = 0
    return ret


# size_t strlen(
#    const char *str
# );
@winsdkapi(cc=CDECL, replace_params={"str": STRING})
def hook_strlen(ql: Qiling, address: int, params):
    s = params["str"]

    return 0 if not s else len(s)


# int strncmp(
#    const char *string1,
#    const char *string2,
#    size_t count
# );
@winsdkapi(cc=CDECL, replace_params={"string1": STRING, "string2": STRING, "count": SIZE_T})
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


# void* malloc（unsigned int size)
@winsdkapi(cc=CDECL, replace_params={"size": UINT})
def hook_malloc(ql: Qiling, address: int, params):
    size = params['size']
    addr = ql.os.heap.alloc(size)
    return addr


# _onexit_t _onexit(
#    _onexit_t function
# );
@winsdkapi(cc=CDECL, replace_params={"function": POINTER})
def hook__onexit(ql: Qiling, address: int, params):
    function = params['function']
    addr = ql.os.heap.alloc(ql.pointersize)
    ql.mem.write(addr, ql.pack(function))
    return addr


# void *memset(
#    void *dest,
#    int c,
#    size_t count
# );
@winsdkapi(cc=CDECL, replace_params={"dest": POINTER, "c": INT, "count": SIZE_T})
def hook_memset(ql: Qiling, address: int, params):
    dest = params["dest"]
    c = params["c"]
    count = params["count"]
    ql.mem.write(dest, bytes(c) * count)
    return dest


# void *calloc(
#    size_t num,
#    size_t size
# );
@winsdkapi(cc=CDECL, replace_params={"num": SIZE_T, "size": SIZE_T})
def hook_calloc(ql: Qiling, address: int, params):
    num = params['num']
    size = params['size']
    ret = ql.os.heap.alloc(num * size)
    return ret


# void * memmove(
#   void *dest,
#   const void *src,
#   size_t num
# );
@winsdkapi(cc=CDECL, replace_params={"dest": POINTER, "src": POINTER, "num": SIZE_T})
def hook_memmove(ql: Qiling, address: int, params):
    data = ql.mem.read(params['src'], params['num'])
    ql.mem.write(params['dest'], bytes(data))
    return params['dest']


# int _ismbblead(
#    unsigned int c
# );
@winsdkapi(cc=CDECL, replace_params={"c": UINT})
def hook__ismbblead(ql: Qiling, address: int, params):
    # TODO check if is CDECL or not
    # If locale is utf-8 always return 0
    loc = LOCALE["default"]
    if loc[0x1004] == "utf-8":
        return 0
    else:
        raise QlErrorNotImplemented("API not implemented")


# errno_t _wfopen_s(
#    FILE** pFile,
#    const wchar_t *filename,
#    const wchar_t *mode
# );
@winsdkapi(cc=CDECL, replace_params={"pFile": POINTER, "filename": WSTRING, "mode": WSTRING})
def hook__wfopen_s(ql: Qiling, address: int, params):
    dst = params["pFile"]
    filename = params["filename"]
    mode = params["mode"]
    f = ql.os.fs_mapper.open(filename, mode)
    new_handle = Handle(obj=f)
    ql.os.handle_manager.append(new_handle)
    ql.mem.write(dst, ql.pack(new_handle.id))
    return 1


# time_t time( time_t *destTime );
@winsdkapi(cc=CDECL, replace_params={"destTime": POINTER})
def hook__time64(ql: Qiling, address: int, params):
    dst = params["destTime"]
    time_wasted = int(time.time())
    if dst != 0:
        ql.mem.write(dst, time_wasted.to_bytes(8, "little"))
    return time_wasted
