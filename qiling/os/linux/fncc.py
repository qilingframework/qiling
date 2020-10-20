#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
from unicorn.x86_const import *
from qiling.os.utils import *


DWORD = 1
UINT = 1
INT = 1
BOOL = 1
SIZE_T = 1
BYTE = 1
ULONGLONG = 2
HANDLE = 3
POINTER = 3
STRING = 4
WSTRING = 5


def read_cstring(ql, address):
    result = ""
    char = ql.mem.read(address, 1)
    while char.decode(errors="ignore") != "\x00":
        address += 1
        result += char.decode(errors="ignore")
        char = ql.mem.read(address, 1)
    return result


def _get_param_by_index(ql, index):
    if ql.archtype == QL_ARCH.X86:
        return _x86_get_params_by_index(ql, index)
    elif ql.archtype == QL_ARCH.X8664:
        return _x8664_get_params_by_index(ql, index)


# TODO: x86 calling convention of Linux kernel?
def _x86_get_params_by_index(ql, index):
    # index starts from 0
    # skip ret_addr
    return ql.stack_read((index + 1) * 4)


def _x86_get_args(ql, number):
    arg_list = []
    for i in range(number):
        # skip ret_addr
        arg_list.append(ql.stack_read((i + 1) * 4))
    if number == 1:
        return arg_list[0]
    else:
        return arg_list


# The kernel interface uses RDI, RSI, RDX, R10, R8 and R9.
def _x8664_get_params_by_index(ql, index):
    reg_list = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
    if index < 6:
        return ql.uc.reg_read(reg_list[index])

    index -= 6
    # skip ret_addr
    return ql.stack_read((index + 1) * 8)


def _x8664_get_args(ql, number):
    reg_list = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
    arg_list = []
    reg_num = number
    if reg_num > 6:
        reg_num = 6
    number -= reg_num
    # get args in registers first
    for i in reg_list[:reg_num]:
        arg_list.append(ql.uc.reg_read(i))
    # the rest args are from stack
    for i in range(number):
        # skip ret_addr and 32 byte home space
        arg_list.append(ql.stack_read((i + 7) * 8))
    if reg_num == 1:
        return arg_list[0]
    else:
        return arg_list


def set_function_params(ql, in_params, out_params):
    index = 0
    for each in in_params:
        if in_params[each] == DWORD or in_params[each] == POINTER:
            out_params[each] = _get_param_by_index(ql, index)
        elif in_params[each] == ULONGLONG:
            if ql.archtype == QL_ARCH.X86:
                low = _get_param_by_index(ql, index)
                index += 1
                high = _get_param_by_index(ql, index)
                out_params[each] = high << 8 + low
            else:
                out_params[each] = _get_param_by_index(ql, index)
        elif in_params[each] == STRING:
            ptr = _get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                out_params[each] = read_cstring(ql, ptr)
        elif in_params[each] == WSTRING:
            ptr = _get_param_by_index(ql, index)
            if ptr == 0:
                out_params[each] = 0
            else:
                out_params[each] = read_wstring(ql, ptr)
        index += 1
    return index


def set_return_value(ql, ret):
    if ql.archtype == QL_ARCH.X86:
        ql.uc.reg_write(UC_X86_REG_EAX, ret)
    elif ql.archtype == QL_ARCH.X8664:
        ql.uc.reg_write(UC_X86_REG_RAX, ret)


def get_return_value(ql):
    if ql.archtype == QL_ARCH.X86:
        return ql.uc.reg_read(UC_X86_REG_EAX)
    elif ql.archtype == QL_ARCH.X8664:
        return ql.uc.reg_read(UC_X86_REG_RAX)


def print_function(ql, passthru, address, function_name, params, ret):
    PRINTK_LEVEL = {
        0: 'KERN_EMERGE',
        1: 'KERN_ALERT',
        1: 'KERN_CRIT',
        2: 'KERN_INFO',
        3: 'KERN_ERR',
        4: 'KERN_WARNING',
        5: 'KERN_NOTICE',
        6: 'KERN_INFO',
        7: 'KERN_DEBUG',
        8: '',
        9: 'KERN_CONT',
    }
    function_name = function_name.replace('hook_', '')
    if function_name in ("__stdio_common_vfprintf", "__stdio_common_vfwprintf",
                         "printf", "wsprintfW", "sprintf"):
        return
    log = '0x%0.2x: %s(' % (address, function_name)
    for each in params:
        value = params[each]
        if type(value) == str or type(value) == bytearray:
            if function_name == 'printk':
                info = value[:2]
                try:
                    level = PRINTK_LEVEL[int(info[1])]
                    value = value[2:]
                    log += '%s = %s "%s", ' %(each, level, value)
                except:
                    log += '%s = "%s", ' %(each, value)
            else:
                log += '%s = "%s", ' %(each, value)
        elif type(value) == tuple:
            log += '%s = 0x%x, ' % (each, value[0])
        else:
            log += '%s = 0x%x, ' % (each, value)
    log = log.strip(", ")
    log += ')'
    if ret is not None:
        # do not print result for printk()
        if function_name != 'printk':
            log += ' = 0x%x' % ret

    if passthru:
        log += ' (PASSTHRU)'

    # replace \n
    log = log.replace("\n", "\\n")
    if ql.output != QL_OUTPUT.DEBUG:
        log = log.partition(" ")[-1]
        ql.nprint(log)
    else:
        ql.dprint(D_INFO, log)


def __x86_cc(ql, param_num, params, func, args, kwargs):
    # read params
    if params is not None:
        param_num = set_function_params(ql, params, args[2])
    # call function
    result = func(*args, **kwargs)
    # set return value
    if result is not None:
        set_return_value(ql, result)
    # print
    print_function(ql, False, args[1], func.__name__, args[2], result)
    return result, param_num


def x86_stdcall(ql, param_num, params, func, args, kwargs):
    # get ret addr
    ret_addr = ql.stack_read(0)

    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)

    # update stack pointer
    ql.reg.arch_sp += (param_num + 1) * 4

    ql.reg.arch_pc = ret_addr

    return result


def x86_cdecl(ql, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)

    ql.reg.arch_pc = ql.stack_pop()

    return result


def x8664_fastcall(ql, param_num, params, func, args, kwargs):
    result, param_num = __x86_cc(ql, param_num, params, func, args, kwargs)

    ql.reg.arch_pc = ql.stack_pop()

    return result


def linux_kernel_api(param_num=None, params=None):
    """
    @cc: windows api calling convention, only x86 needs this, x64 is always fastcall
    @params: params dict
    @param_num: the number of function params, used by variadic functions, e.g printf
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            ql = args[0]
            if ql.archtype == QL_ARCH.X86:
                # if cc == STDCALL:
                return x86_stdcall(ql, param_num, params, func, args, kwargs)
                #elif cc == CDECL:
                #    return x86_cdecl(ql, param_num, params, func, args, kwargs)
            elif ql.archtype == QL_ARCH.X8664:
                return x8664_fastcall(ql, param_num, params, func, args, kwargs)
            else:
                raise QlErrorArch("[!] Unknown ql.archtype")
        return wrapper
    return decorator

