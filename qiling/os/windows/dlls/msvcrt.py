#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import os
import time


from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.const import *

dllname = 'msvcrt_dll'

# void __set_app_type (
#    int at
# )
@winsdkapi(cc=CDECL)
def hook___set_app_type(ql, address, params):
    pass


# int __getmainargs(
#     int * _Argc,
#    char *** _Argv,
#    char *** _Env,
#    int _DoWildCard,
# _startupinfo * _StartInfo);
@winsdkapi(cc=CDECL,
    replace_params={"_Argc": POINTER, "_Argv": POINTER, "_Env": POINTER, "_DoWildCard": INT, "_StartInfo": POINTER})
def hook___getmainargs(ql, address, params):
    ret = 0
    return ret


# int* __p__fmode(
# );
@winsdkapi(cc=CDECL)
def hook___p__fmode(ql, address, params):
    addr = ql.os.heap.alloc(ql.pointersize)
    return addr


# int * __p__commode(
#    );
@winsdkapi(cc=CDECL)
def hook___p__commode(ql, address, params):
    addr = ql.os.heap.alloc(ql.pointersize)
    return addr


# int * __p__acmdln(
#    );
@winsdkapi(cc=CDECL)
def hook___p__acmdln(self, address, params):
    addr = self.ql.loader.import_address_table['msvcrt.dll'][b'_acmdln']
    return addr


# unsigned int _controlfp(
#    unsigned int new,
#    unsigned int mask
# );
@winsdkapi(cc=CDECL, replace_params={"new": UINT, "mask": UINT})
def hook__controlfp(ql, address, params):
    ret = 0x8001f
    return ret


# int atexit(
#    void (__cdecl *func)(void)
# );
@winsdkapi(cc=CDECL, replace_params={"func": POINTER})
def hook_atexit(ql, address, params):
    ret = 0
    return ret


# char*** __p__environ(void)
@winsdkapi(cc=CDECL)
def hook___p__environ(ql, address, params):
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
def hook_puts(ql, address, params):
    ret = 0
    string = params["str"]
    ql.os.stdout.write(bytes(string + "\n", "utf-8"))
    ret = len(string) + 1
    return ret


# void _cexit( void );
@winsdkapi(cc=CDECL)
def hook__cexit(ql, address, params):
    pass


# void __cdecl _initterm(
#    PVFV *,
#    PVFV *
# );
@winsdkapi(cc=CDECL, replace_params={"pfbegin": POINTER, "pfend": POINTER})
def hook__initterm(ql, address, params):
    pass


# void exit(
#    int const status
# );
@winsdkapi(cc=CDECL, replace_params={"status": INT})
def hook_exit(ql, address, params):
    ql.emu_stop()
    ql.os.PE_RUN = False


# int __cdecl _initterm_e(
#    PVFV *,
#    PVFV *
# );
@winsdkapi(cc=CDECL, replace_params={"pfbegin": POINTER, "pfend": POINTER})
def hook__initterm_e(ql, address, params):
    return 0


# char***    __cdecl __p___argv (void);
@winsdkapi(cc=CDECL)
def hook___p___argv(ql, address, params):
    ret = ql.os.heap.alloc(ql.pointersize * len(ql.argv))
    count = 0
    for each in ql.argv:
        arg_pointer = ql.os.heap.alloc(ql.pointersize)
        arg = ql.os.heap.alloc(len(each) + 1)
        ql.mem.write(arg, bytes(each, 'ascii') + b'\x00')
        ql.mem.write(arg_pointer, ql.pack(arg))
        ql.mem.write(ret + count * ql.pointersize, ql.pack(arg_pointer))
        count += 1
    return ret


# int* __p___argc(void)
@winsdkapi(cc=CDECL)
def hook___p___argc(ql, address, params):
    ret = ql.os.heap.alloc(ql.pointersize)
    ql.mem.write(ret, ql.pack(len(ql.argv)))
    return ret


@winsdkapi(cc=CDECL)
def hook__get_initial_narrow_environment(ql, address, params):
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
@winsdkapi(cc=CDECL, dllname=dllname, param_num=3)
def hook_sprintf(ql, address, _):
    ret = 0
    str_ptr, format_ptr = ql.os.get_function_param(2)

    if not format_ptr:
        ql.nprint('printf(format = 0x0) = 0x%x' % ret)
        return ret

    sp = ql.reg.esp if ql.archtype == QL_ARCH.X86 else ql.reg.rsp
    p_args = sp + ql.pointersize * 3

    format_string = ql.os.read_cstring(format_ptr)
    str_size, str_data = ql.os.printf(address, format_string, p_args, "sprintf")
    ql.nprint()

    count = format_string.count('%')
    if ql.archtype == QL_ARCH.X8664:
        if count + 1 > 4:
            ql.reg.rsp = ql.reg.rsp + ((count - 4 + 1) * 8)

    ql.mem.write(str_ptr, str_data.encode('utf-8') + b'\x00')
    ret = str_size
    
    return ret


# int printf(const char *format, ...)
@winsdkapi(cc=CDECL, param_num=1)
def hook_printf(ql, address, _):
    ret = 0
    format_string = ql.os.get_function_param(1)

    if format_string == 0:
        ql.nprint('printf(format = 0x0) = 0x%x' % ret)
        return ret

    format_string = ql.os.read_cstring(format_string)

    param_addr = ql.reg.arch_sp + ql.pointersize * 2
    ret, _ = ql.os.printf(address, format_string, param_addr, "printf")

    ql.os.set_return_value(ret)

    count = format_string.count('%')
    # x8664 fastcall donnot known the real number of parameters
    # so you need to manually pop the stack
    if ql.archtype == QL_ARCH.X8664:
        # if number of params > 4
        if count + 1 > 4:
            ql.reg.rsp = ql.reg.rsp + ((count - 4 + 1) * 8)

    return None


# MSVCRT_FILE * CDECL MSVCRT___acrt_iob_func(unsigned idx)
@winsdkapi(cc=CDECL, replace_params={"idx": UINT})
def hook___acrt_iob_func(ql, address, params):
    ret = 0
    return ret


@winsdkapi(cc=CDECL, param_num=2)
def hook___stdio_common_vfprintf(ql, address, _):
    ret = 0
    if ql.pointersize == 8:
        _, _, p_format, _, p_args = ql.os.get_function_param(5)
    else:
        _, _, _, p_format, _, p_args = ql.os.get_function_param(6)
    fmt = ql.os.read_cstring(p_format)
    ql.os.printf(address, fmt, p_args, '__stdio_common_vfprintf')
    return ret


@winsdkapi(cc=CDECL, param_num=4)
def hook___stdio_common_vfwprintf(ql, address, _):
    ret = 0
    _, _, _, p_format, _, p_args = ql.os.get_function_param(6)
    fmt = ql.os.read_wstring(p_format)

    ql.os.printf(address, fmt, p_args, '__stdio_common_vfwprintf', wstring=True)
    return ret


@winsdkapi(cc=CDECL, param_num=4)
def hook___stdio_common_vswprintf_s(ql, address, _):
    ret = 0
    _, size, p_format, p_args = ql.os.get_function_param(4)

    fmt = ql.os.read_wstring(p_format)
    ql.os.printf(address, fmt, p_args, '__stdio_common_vswprintf_s', wstring=True)

    return ret


# int lstrlenA(
#   LPCSTR lpString
# );
@winsdkapi(cc=CDECL, replace_params={'lpString': POINTER})
def hook_lstrlenA(ql, address, params):
    addr = params["lpString"]
    string = b""
    val = ql.mem.read(addr, 1)
    while bytes(val) != b"\x00":
        addr += 1
        string += bytes(val)
        val = ql.mem.read(addr, 1)
    params["lpString"] = bytearray(string)
    return len(string)


# int lstrlenW(
#   LPCWSTR lpString
# );
@winsdkapi(cc=CDECL, replace_params={'lpString': POINTER})
def hook_lstrlenW(ql, address, params):
    addr = params["lpString"]
    string = b""
    val = ql.mem.read(addr, 2)
    while bytes(val) != b"\x00\x00":
        addr += 2
        string += bytes(val)
        val = ql.mem.read(addr, 2)
    params["lpString"] = bytearray(string)
    return len(string)


@winsdkapi(cc=CDECL)
def hook___lconv_init(ql, address, params):
    ret = 0
    return ret


# size_t strlen(
#    const char *str
# );
@winsdkapi(cc=CDECL, replace_params={"str": STRING})
def hook_strlen(ql, address, params):
    _str = params["str"]
    strlen = len(_str)
    return strlen


# int strncmp(
#    const char *string1,
#    const char *string2,
#    size_t count
# );
@winsdkapi(cc=CDECL, replace_params={"string1": STRING, "string2": STRING, "count": SIZE_T})
def hook_strncmp(ql, address, params):
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
def hook_malloc(ql, address, params):
    size = params['size']
    addr = ql.os.heap.alloc(size)
    return addr


# _onexit_t _onexit(
#    _onexit_t function
# );
@winsdkapi(cc=CDECL, replace_params={"function": POINTER})
def hook__onexit(ql, address, params):
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
def hook_memset(ql, address, params):
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
def hook_calloc(ql, address, params):
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
def hook_memmove(ql, address, params):
    data = ql.mem.read(params['src'], params['num'])
    ql.mem.write(params['dest'], bytes(data))
    return params['dest']


# int _ismbblead(
#    unsigned int c
# );
@winsdkapi(cc=CDECL, replace_params={"c": UINT})
def hook__ismbblead(ql, address, params):
    # TODO check if is CDECL or not
    # If locale is utf-8 always return 0
    loc = LOCALE["default"]
    if loc[0x1004] == "utf-8":
        return 0
    else:
        raise QlErrorNotImplemented("[!] API not implemented")


# errno_t _wfopen_s(
#    FILE** pFile,
#    const wchar_t *filename,
#    const wchar_t *mode
# );
@winsdkapi(cc=CDECL, replace_params={"pFile": POINTER, "filename": WSTRING, "mode": WSTRING})
def hook__wfopen_s(ql, address, params):
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
def hook__time64(ql, address, params):
    dst = params["destTime"]
    time_wasted = int(time.time())
    if dst != 0:
        ql.mem.write(dst, time_wasted.to_bytes(8, "little"))
    return time_wasted
