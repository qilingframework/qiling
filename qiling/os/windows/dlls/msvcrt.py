#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

import struct
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *


# void __set_app_type (
#    int at
# )
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=1)
def hook___set_app_type(ql, address):
    at = ql.get_params(1)
    ql.nprint('0x%0.2x: __set_app_type(0x%x)' % (address, at))


# int __getmainargs(
#     int * _Argc,
#    char *** _Argv,
#    char *** _Env,
#    int _DoWildCard,
# _startupinfo * _StartInfo);
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=5)
def hook___getmainargs(ql, address):
    ret = 0
    _Argc, _Argv, _Env, _DoWildCard, _StartInfo = ql.get_params(5)
    ql.nprint('0x%0.2x: __getmainargs(0x%x, 0x%x, 0x%x, 0x%x, 0x%x) = %d' % (address, _Argc, _Argv, _Env, _DoWildCard, _StartInfo, ret))
    return ret


@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=0)
def hook___p__fmode(ql, address):
    addr = ql.heap.mem_alloc(ql.pointersize)
    ql.nprint('0x%0.2x: __p__fmode() = 0x%x' % (address, addr))
    return addr


@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=0)
def hook___p__commode(ql, address):
    addr = ql.heap.mem_alloc(ql.pointersize)
    ql.nprint('0x%0.2x: __p__commode() = 0x%x' % (address, addr))
    return addr


# unsigned int _controlfp(
#    unsigned int new,
#    unsigned int mask
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=2)
def hook__controlfp(ql, address):
    ret = 0x8001f
    new , mask = ql.get_params(2)
    ql.nprint('0x%0.2x: _controlfp(0x%x, 0x%x) = 0x%x' % (address, new, mask, ret))
    return ret

# int atexit(
#    void (__cdecl *func)(void)
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=1)
def hook_atexit(ql, address):
    ret = 0
    func = ql.get_params(1)
    ql.nprint('0x%0.2x: atexit(0x%x) = %d' % (address, func, ret))
    return ret


@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=0)
def hook___p__environ(ql, address):
    ret = ql.heap.mem_alloc(ql.pointersize * len(ql.env))
    count = 0
    for key in ql.env:
        pointer = ql.heap.mem_alloc(ql.pointersize)
        env = key + "=" + ql.env[key]
        env_addr = ql.heap.mem_alloc(len(env)+1)
        ql.mem_write(env_addr, bytes(env, 'ascii') + b'\x00')
        ql.mem_write(pointer, ql.pack(env_addr))
        ql.mem_write(ret + count * ql.pointersize, ql.pack(pointer))
        count += 1
    ql.nprint('0x%0.2x: __p__environ() = 0x%x' % (address, ret))
    return ret


# int puts(
#    const char *str
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=1)
def hook_puts(ql, address):
    ret = 0
    string_addr = ql.get_params(1)
    string = read_cstring(ql, string_addr)
    ret = len(string)
    ql.nprint('0x%0.2x: puts(0x%x=\"%s\") = %d' % (address, string_addr, string, ret))
    return ret

@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=0)
def hook__cexit(ql, address):
    ql.nprint('0x%0.2x: cexit()' % (address))


# void __cdecl _initterm(
#    PVFV *,
#    PVFV *
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=2)
def hook__initterm(ql, address):
    pfbegin, pfend = ql.get_params(2)
    ql.nprint('0x%0.2x: _initterm(0x%x, 0x%x)' % (address, pfbegin, pfend))


# void exit(
#    int const status
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=1)
def hook_exit(ql, address):
    status = ql.get_params(1)
    ql.nprint('0x%0.2x: exit(0x%x)' % (address, status))
    ql.uc.emu_stop()
    ql.RUN = False


# int __cdecl _initterm_e(
#    PVFV *,
#    PVFV *
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=2)
def hook__initterm_e(ql, address):
    pfbegin, pfend = ql.get_params(2)
    ql.nprint('0x%0.2x: _initterm_e(0x%x, 0x%x) = 0x%x' % (address, pfbegin, pfend, 0))
    return 0


# char***    __cdecl __p___argv (void);
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=0)
def hook___p___argv(ql, address):
    ret = ql.heap.mem_alloc(ql.pointersize * len(ql.argv))
    count = 0
    for each in ql.argv:
        arg_pointer = ql.heap.mem_alloc(ql.pointersize)
        arg = ql.heap.mem_alloc(len(each)+1)
        ql.mem_write(arg, bytes(each, 'ascii') + b'\x00')
        ql.mem_write(arg_pointer, ql.pack(arg))
        ql.mem_write(ret + count * ql.pointersize, ql.pack(arg_pointer))
        count += 1
    ql.nprint('0x%0.2x: __p___argv() = 0x%x' % (address, ret))
    return ret


# int* __p___argc(void)
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=0)
def hook___p___argc(ql, address):
    ret = ql.heap.mem_alloc(ql.pointersize)
    ql.mem_write(ret, ql.pack(len(ql.argv)))
    ql.nprint('0x%0.2x: __p___argc() = 0x%x' % (address, ret))
    return ret


@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=0)
def hook__get_initial_narrow_environment(ql, address):
    ret = 0
    count = 0
    for key in ql.env:
        value = key + "=" + ql.env[key]
        env = ql.heap.mem_alloc(len(value)+1)
        if count == 0:
            ret = env
        ql.mem_write(env, bytes(value, 'ascii') + b'\x00')
        count += 1
    ql.nprint('0x%0.2x: _get_initial_narrow_environment() = 0x%x' % (address, ret))
    return ret


def printf(ql, address, fmt, params_addr, name):
    count = fmt.count("%")
    params = []
    if count > 0:
        for i in range(count):
            params.append(ql.unpack(
                ql.uc.mem_read(
                    params_addr + i * ql.pointersize,
                    ql.pointersize
                )
            ))

        formats = fmt.split("%")[1:]
        index = 0
        for f in formats:
            if f.startswith("s"):
                params[index] = read_cstring(ql, params[index])
            index += 1

        output = '0x%0.2x: %s(format = %s' % (address, name, repr(fmt))
        for each in params:
            if type(each) == str:
                output += ', "%s"' % each
            else:
                output += ', 0x%0.2x' % each
        output += ')'
        fmt = fmt.replace("%llx", "%x")
        stdout = fmt % tuple(params)
        output += " = 0x%x" % len(stdout)
    else:
        output = '0x%0.2x: %s(format = %s) = 0x%x' % (address, name, repr(fmt), len(fmt))
        stdout = fmt
    ql.nprint(output)
    ql.stdout.write(bytes(stdout, 'utf-8'))
    return len(stdout)


# int printf(const char *format, ...)
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=1)
def hook_printf(ql, address):
    ret = 0
    format_string = ql.get_params(1)

    if format_string == 0:
        ql.nprint('0x%0.2x: printf(format = 0x0) = 0x%x' % (address, ret))
        return ret

    format_string = read_cstring(ql, format_string)

    param_addr = ql.sp + ql.pointersize * 2
    ret = printf(ql, address, format_string, param_addr, "printf")

    ql.set_return_value(ret)

    count = format_string.count('%')
    # x8664 fastcall donnot known the real number of parameters
    # so you need to manually pop the stack
    if ql.arch == QL_X8664:
        # if number of params > 4
        if count + 1 > 4:
            rsp = ql.uc.reg_read(UC_X86_REG_RSP)
            ql.uc.reg_write(UC_X86_REG_RSP, rsp + (count - 4 + 1) * 8)

    return None

# MSVCRT_FILE * CDECL MSVCRT___acrt_iob_func(unsigned idx)
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=1)
def hook___acrt_iob_func(ql, address):
    ret = 0
    idx = ql.get_params(1)
    ql.nprint('0x%0.2x: __acrt_iob_func(0x%x) = 0x%x' % (address, idx, ret))
    return ret


@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=2)
def hook___stdio_common_vfprintf(ql, address):
    ret = 0
    _, _, _, p_format, _, p_args = ql.get_params(6)
    fmt = read_cstring(ql, p_format)
    printf(ql, address, fmt, p_args, '__stdio_common_vfprintf')
    return ret


# int lstrlenW(
#   LPCWSTR lpString
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=1)
def hook_lstrlenW(ql, address):
    ret = 0
    lpString = ql.get_params(1)
    if lpString == 0:
        ret = 0
        ql.nprint('0x%0.2x: lstrlenW(0x0) = 0x%x' % (address, ret))
    else:
        string = read_wstring(ql, lpString)
        ret = len(string)
        ql.nprint('0x%0.2x: lstrlenW(%s) = 0x%x' % (address, repr(string), ret))
    return ret


@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=0)
def hook___lconv_init(ql, address):
    ret = 0
    ql.nprint('0x%0.2x: __lconv_init() = %d' % (address, ret))
    return ret


# size_t strlen(
#    const char *str
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=1)
def hook_strlen(ql, address):
    _str = ql.get_params(1)
    string1 = read_cstring(ql, _str)
    strlen = len(string1)
    ql.nprint('0x%0.2x: strlen(0x%x=\"%s\") = %d' % (address, _str, string1, strlen))
    return strlen


# int strncmp(
#    const char *string1,
#    const char *string2,
#    size_t count
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=3)
def hook_strncmp(ql, address):
    s1, s2, count = ql.get_params(3)
    string1 = ql.uc.mem_read(s1, count).decode()
    string2 = ql.uc.mem_read(s2, count).decode()

    if string1 == string2:
        result = 0
    elif string1 > string2:
        result = 1
    else:
        result = -1

    ql.nprint('0x%0.2x: strncmp(0x%x=\"%s\", 0x%x=\"%s\", 0x%x) = %d' % (address, s1, string1, s2, string2, count, result))
    return result


@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=1)
def hook_malloc(ql, address):
    size = ql.get_params(1)
    addr = ql.heap.mem_alloc(size)
    ql.nprint('0x%0.2x: malloc(0x%x) = 0x%x' % (address, size, addr))
    return addr


# _onexit_t _onexit(
#    _onexit_t function
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=1)
def hook__onexit(ql, address):
    function = ql.get_params(1)
    addr = ql.heap.mem_alloc(ql.pointersize)
    ql.uc.mem_write(addr, ql.pack(function))
    ql.nprint('0x%0.2x: _onexit(0x%x) = 0x%x' % (address, function, addr))
    return addr


# void *memset(
#    void *dest,
#    int c,
#    size_t count
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=3)
def hook_memset(ql, address):
    dest, c, count = ql.get_params(3)
    ql.uc.mem_write(dest, bytes(c) * count)
    ql.nprint('0x%0.2x: memset(0x%x, 0x%x, 0x%x) = 0x%x' % (address, dest, c, count, dest))
    return dest


# void *calloc(
#    size_t num,
#    size_t size
# );
@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, param_num=2)
def hook_calloc(ql, address):
    num, size = ql.get_params(2)
    ret = ql.heap.mem_alloc(num * size)
    ql.nprint('0x%0.2x: calloc(0x%x, 0x%x) = 0x%x' % (address, num, size, ret))
    return ret