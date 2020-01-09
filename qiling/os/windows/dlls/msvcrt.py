#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from qiling.os.windows.fncc import *
from qiling.os.fncc import *


# void __set_app_type (
#    int at
# )
@winapi(cc=CDECL, params={
    "at": INT
})
def hook___set_app_type(ql, address, params):
    pass


# int __getmainargs(
#     int * _Argc,
#    char *** _Argv,
#    char *** _Env,
#    int _DoWildCard,
# _startupinfo * _StartInfo);
@winapi(cc=CDECL, params={
    "_Argc": POINTER,
    "_Argv": POINTER,
    "_Env": POINTER,
    "_DoWildCard": INT,
    "_StartInfo": POINTER
})
def hook___getmainargs(ql, address, params):
    ret = 0
    return ret


# int* __p__fmode(
# );
@winapi(cc=CDECL, params={})
def hook___p__fmode(ql, address, params):
    addr = ql.heap.mem_alloc(ql.pointersize)
    return addr


# int * __p__commode(
#    );
@winapi(cc=CDECL, params={})
def hook___p__commode(ql, address, params):
    addr = ql.heap.mem_alloc(ql.pointersize)
    return addr


# unsigned int _controlfp(
#    unsigned int new,
#    unsigned int mask
# );
@winapi(cc=CDECL, params={
    "new": UINT,
    "mask": UINT
})
def hook__controlfp(ql, address, params):
    ret = 0x8001f
    return ret


# int atexit(
#    void (__cdecl *func)(void)
# );
@winapi(cc=CDECL, params={
    "func": POINTER
})
def hook_atexit(ql, address, params):
    ret = 0
    return ret


# char*** __p__environ(void)
@winapi(cc=CDECL, params={})
def hook___p__environ(ql, address, params):
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
    return ret


# int puts(
#    const char *str
# );
@winapi(cc=CDECL, params={
    "str": STRING
})
def hook_puts(ql, address, params):
    ret = 0
    string = params["str"]
    ql.stdout.write(bytes(string + "\n", "utf-8"))
    ret = len(string) + 1
    return ret


# void _cexit( void );
@winapi(cc=CDECL, params={})
def hook__cexit(ql, address, params):
    pass


# void __cdecl _initterm(
#    PVFV *,
#    PVFV *
# );
@winapi(cc=CDECL, params={
    "pfbegin": POINTER,
    "pfend": POINTER
})
def hook__initterm(ql, address, params):
    pass

# void exit(
#    int const status
# );
@winapi(cc=CDECL, params={
    "status": INT
})
def hook_exit(ql, address, params):
    ql.uc.emu_stop()
    ql.RUN = False


# int __cdecl _initterm_e(
#    PVFV *,
#    PVFV *
# );
@winapi(cc=CDECL, params={
    "pfbegin": POINTER,
    "pfend": POINTER
})
def hook__initterm_e(ql, address, params):
    return 0


# char***    __cdecl __p___argv (void);
@winapi(cc=CDECL, params={})
def hook___p___argv(ql, address, params):
    ret = ql.heap.mem_alloc(ql.pointersize * len(ql.argv))
    count = 0
    for each in ql.argv:
        arg_pointer = ql.heap.mem_alloc(ql.pointersize)
        arg = ql.heap.mem_alloc(len(each)+1)
        ql.mem_write(arg, bytes(each, 'ascii') + b'\x00')
        ql.mem_write(arg_pointer, ql.pack(arg))
        ql.mem_write(ret + count * ql.pointersize, ql.pack(arg_pointer))
        count += 1
    return ret


# int* __p___argc(void)
@winapi(cc=CDECL, params={})
def hook___p___argc(ql, address, params):
    ret = ql.heap.mem_alloc(ql.pointersize)
    ql.mem_write(ret, ql.pack(len(ql.argv)))
    return ret


@winapi(cc=CDECL, params={})
def hook__get_initial_narrow_environment(ql, address, params):
    ret = 0
    count = 0
    for key in ql.env:
        value = key + "=" + ql.env[key]
        env = ql.heap.mem_alloc(len(value)+1)
        if count == 0:
            ret = env
        ql.mem_write(env, bytes(value, 'ascii') + b'\x00')
        count += 1
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
@winapi(cc=CDECL, param_num=1)
def hook_printf(ql, address, _):
    ret = 0
    format_string = get_function_param(ql, 1)

    if format_string == 0:
        ql.nprint('0x%0.2x: printf(format = 0x0) = 0x%x' % (address, ret))
        return ret

    format_string = read_cstring(ql, format_string)

    param_addr = ql.sp + ql.pointersize * 2
    ret = printf(ql, address, format_string, param_addr, "printf")

    set_return_value(ql, ret)

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
@winapi(cc=CDECL, params={
    "idx": UINT
})
def hook___acrt_iob_func(ql, address, params):
    ret = 0
    return ret


@winapi(cc=CDECL, param_num=2)
def hook___stdio_common_vfprintf(ql, address, _):
    ret = 0
    if ql.pointersize == 8:
        _, _, p_format, _, p_args = get_function_param(ql, 5)
    else:
        _, _, _, p_format, _, p_args = get_function_param(ql, 6)
    fmt = read_cstring(ql, p_format)
    printf(ql, address, fmt, p_args, '__stdio_common_vfprintf')
    return ret


# int lstrlenW(
#   LPCWSTR lpString
# );
@winapi(cc=CDECL, params={
    'lpString': WSTRING
})
def hook_lstrlenW(ql, address, params):
    ret = 0
    string = params["lpString"]
    if string == 0:
        ret = 0
    else:
        ret = len(string)
    return ret


@winapi(cc=CDECL, params={})
def hook___lconv_init(ql, address, params):
    ret = 0
    return ret


# size_t strlen(
#    const char *str
# );
@winapi(cc=CDECL, params={
    "str": STRING
})
def hook_strlen(ql, address, params):
    _str = params["str"]
    strlen = len(_str)
    return strlen


# int strncmp(
#    const char *string1,
#    const char *string2,
#    size_t count
# );
@winapi(cc=CDECL, params={
    "string1": STRING,
    "string2": STRING,
    "count": SIZE_T
})
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
@winapi(cc=CDECL, params={
    "size": UINT
})
def hook_malloc(ql, address, params):
    size = params['size']
    addr = ql.heap.mem_alloc(size)
    return addr


# _onexit_t _onexit(
#    _onexit_t function
# );
@winapi(cc=CDECL, params={
    "function": POINTER
})
def hook__onexit(ql, address, params):
    function = params['function']
    addr = ql.heap.mem_alloc(ql.pointersize)
    ql.uc.mem_write(addr, ql.pack(function))
    return addr


# void *memset(
#    void *dest,
#    int c,
#    size_t count
# );
@winapi(cc=CDECL, params={
    "dest": POINTER,
    "c": INT,
    "count": SIZE_T
})
def hook_memset(ql, address, params):
    dest = params["dest"]
    c = params["c"]
    count = params["count"]
    ql.uc.mem_write(dest, bytes(c) * count)
    return dest


# void *calloc(
#    size_t num,
#    size_t size
# );
@winapi(cc=CDECL, params={
    "num": SIZE_T,
    "size": SIZE_T
})
def hook_calloc(ql, address, params):
    num = params['num']
    size = params['size']
    ret = ql.heap.mem_alloc(num * size)
    return ret


# void * memmove(
#   void *dest,
#   const void *src,
#   size_t num
# );
@winapi(cc=CDECL, params={
    "dest": POINTER,
    "src": POINTER,
    "num": SIZE_T
})
def hook_memmove(ql, address, params):
    data = ql.mem_read(params['src'], params['num'])
    ql.mem_write(params['dest'], bytes(data))
    return params['dest']
