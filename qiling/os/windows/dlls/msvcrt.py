#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from qiling.os.utils import *
from qiling.os.windows.fncc import *
from qiling.os.fncc import *
from qiling.os.windows.const import *


# void __set_app_type (
#    int at
# )
@winapi(cc=CDECL, params={
    "at": INT
})
def hook___set_app_type(self, address, params):
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
def hook___getmainargs(self, address, params):
    ret = 0
    return ret


# int* __p__fmode(
# );
@winapi(cc=CDECL, params={})
def hook___p__fmode(self, address, params):
    addr = self.ql.os.heap.mem_alloc(self.ql.pointersize)
    return addr


# int * __p__commode(
#    );
@winapi(cc=CDECL, params={})
def hook___p__commode(self, address, params):
    addr = self.ql.os.heap.mem_alloc(self.ql.pointersize)
    return addr


# unsigned int _controlfp(
#    unsigned int new,
#    unsigned int mask
# );
@winapi(cc=CDECL, params={
    "new": UINT,
    "mask": UINT
})
def hook__controlfp(self, address, params):
    ret = 0x8001f
    return ret


# int atexit(
#    void (__cdecl *func)(void)
# );
@winapi(cc=CDECL, params={
    "func": POINTER
})
def hook_atexit(self, address, params):
    ret = 0
    return ret


# char*** __p__environ(void)
@winapi(cc=CDECL, params={})
def hook___p__environ(self, address, params):
    ret = self.ql.os.heap.mem_alloc(self.ql.pointersize * len(self.ql.env))
    count = 0
    for key in self.ql.env:
        pointer = self.ql.os.heap.mem_alloc(self.ql.pointersize)
        env = key + "=" + self.ql.env[key]
        env_addr = self.ql.os.heap.mem_alloc(len(env) + 1)
        self.ql.mem.write(env_addr, bytes(env, 'ascii') + b'\x00')
        self.ql.mem.write(pointer, self.ql.pack(env_addr))
        self.ql.mem.write(ret + count * self.ql.pointersize, self.ql.pack(pointer))
        count += 1
    return ret


# int puts(
#    const char *str
# );
@winapi(cc=CDECL, params={
    "str": STRING
})
def hook_puts(self, address, params):
    ret = 0
    string = params["str"]
    self.ql.stdout.write(bytes(string + "\n", "utf-8"))
    ret = len(string) + 1
    return ret


# void _cexit( void );
@winapi(cc=CDECL, params={})
def hook__cexit(self, address, params):
    pass


# void __cdecl _initterm(
#    PVFV *,
#    PVFV *
# );
@winapi(cc=CDECL, params={
    "pfbegin": POINTER,
    "pfend": POINTER
})
def hook__initterm(self, address, params):
    pass


# void exit(
#    int const status
# );
@winapi(cc=CDECL, params={
    "status": INT
})
def hook_exit(self, address, params):
    self.ql.uc.emu_stop()
    self.PE_RUN = False


# int __cdecl _initterm_e(
#    PVFV *,
#    PVFV *
# );
@winapi(cc=CDECL, params={
    "pfbegin": POINTER,
    "pfend": POINTER
})
def hook__initterm_e(self, address, params):
    return 0


# char***    __cdecl __p___argv (void);
@winapi(cc=CDECL, params={})
def hook___p___argv(self, address, params):
    ret = self.ql.os.heap.mem_alloc(self.ql.pointersize * len(self.ql.argv))
    count = 0
    for each in self.ql.argv:
        arg_pointer = self.ql.os.heap.mem_alloc(self.ql.pointersize)
        arg = self.ql.os.heap.mem_alloc(len(each) + 1)
        self.ql.mem.write(arg, bytes(each, 'ascii') + b'\x00')
        self.ql.mem.write(arg_pointer, self.ql.pack(arg))
        self.ql.mem.write(ret + count * self.ql.pointersize, self.ql.pack(arg_pointer))
        count += 1
    return ret


# int* __p___argc(void)
@winapi(cc=CDECL, params={})
def hook___p___argc(self, address, params):
    ret = self.ql.os.heap.mem_alloc(self.ql.pointersize)
    self.ql.mem.write(ret, self.ql.pack(len(self.ql.argv)))
    return ret


@winapi(cc=CDECL, params={})
def hook__get_initial_narrow_environment(self, address, params):
    ret = 0
    count = 0
    for key in self.ql.env:
        value = key + "=" + self.ql.env[key]
        env = self.ql.os.heap.mem_alloc(len(value) + 1)
        if count == 0:
            ret = env
        self.ql.mem.write(env, bytes(value, 'ascii') + b'\x00')
        count += 1
    return ret


# int printf(const char *format, ...)
@winapi(cc=CDECL, param_num=1)
def hook_printf(self, address, _):
    ret = 0
    format_string = get_function_param(self, 1)

    if format_string == 0:
        self.ql.nprint('0x%0.2x: printf(format = 0x0) = 0x%x' % (address, ret))
        return ret

    format_string = read_cstring(self, format_string)

    param_addr = self.ql.sp + self.ql.pointersize * 2
    ret, _ = printf(self, address, format_string, param_addr, "printf")

    set_return_value(self, ret)

    count = format_string.count('%')
    # x8664 fastcall donnot known the real number of parameters
    # so you need to manually pop the stack
    if self.ql.archtype== QL_X8664:
        # if number of params > 4
        if count + 1 > 4:
            rsp = self.ql.register(UC_X86_REG_RSP)
            self.ql.register(UC_X86_REG_RSP, rsp + (count - 4 + 1) * 8)

    return None


# MSVCRT_FILE * CDECL MSVCRT___acrt_iob_func(unsigned idx)
@winapi(cc=CDECL, params={
    "idx": UINT
})
def hook___acrt_iob_func(self, address, params):
    ret = 0
    return ret


@winapi(cc=CDECL, param_num=2)
def hook___stdio_common_vfprintf(self, address, _):
    ret = 0
    if self.ql.pointersize == 8:
        _, _, p_format, _, p_args = get_function_param(self, 5)
    else:
        _, _, _, p_format, _, p_args = get_function_param(self, 6)
    fmt = read_cstring(self, p_format)
    printf(self, address, fmt, p_args, '__stdio_common_vfprintf')
    return ret


# int lstrlenW(
#   LPCWSTR lpString
# );
@winapi(cc=CDECL, params={
    'lpString': WSTRING
})
def hook_lstrlenW(self, address, params):
    ret = 0
    string = params["lpString"]
    if string == 0:
        ret = 0
    else:
        ret = len(string)
    return ret


@winapi(cc=CDECL, params={})
def hook___lconv_init(self, address, params):
    ret = 0
    return ret


# size_t strlen(
#    const char *str
# );
@winapi(cc=CDECL, params={
    "str": STRING
})
def hook_strlen(self, address, params):
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
def hook_strncmp(self, address, params):
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
def hook_malloc(self, address, params):
    size = params['size']
    addr = self.ql.os.heap.mem_alloc(size)
    return addr


# _onexit_t _onexit(
#    _onexit_t function
# );
@winapi(cc=CDECL, params={
    "function": POINTER
})
def hook__onexit(self, address, params):
    function = params['function']
    addr = self.ql.os.heap.mem_alloc(self.ql.pointersize)
    self.ql.mem.write(addr, self.ql.pack(function))
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
def hook_memset(self, address, params):
    dest = params["dest"]
    c = params["c"]
    count = params["count"]
    self.ql.mem.write(dest, bytes(c) * count)
    return dest


# void *calloc(
#    size_t num,
#    size_t size
# );
@winapi(cc=CDECL, params={
    "num": SIZE_T,
    "size": SIZE_T
})
def hook_calloc(self, address, params):
    num = params['num']
    size = params['size']
    ret = self.ql.os.heap.mem_alloc(num * size)
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
def hook_memmove(self, address, params):
    data = self.ql.mem.read(params['src'], params['num'])
    self.ql.mem.write(params['dest'], bytes(data))
    return params['dest']


# int _ismbblead(
#    unsigned int c
# );
@winapi(cc=CDECL, params={
    "c": UINT
})
def hook__ismbblead(self, address, params):
    # TODO check if is CDECL or not
    # If locale is utf-8 always return 0
    loc = LOCALE["default"]
    if loc[0x1004] == "utf-8":
        return 0
    else:
        raise QlErrorNotImplemented("[!] API not implemented")
