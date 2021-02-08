#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes, os, struct

from unicorn.x86_const import *
from unicorn.arm_const import *

from qiling.os.const import *
from qiling.const import *
from qiling.os.macos.structs import IOExternalMethodArguments, IOExternalMethodDispatch, POINTER64

def IOConnectCallMethod(ql, selector, 
                        input_array, input_cnt, input_struct, input_struct_size,
                        output_array, output_cnt, output_struct, output_struct_size):

    if ql.os.IOKit is not True:
        ql.log.info("Must have a IOKit driver")
        return output_array, output_struct

    args_addr = ql.os.heap.alloc(ctypes.sizeof(IOExternalMethodArguments))
    ql.log.debug("Created IOExternalMethodArguments object at 0x%x" % args_addr)
    args_obj = IOExternalMethodArguments(ql, args_addr)

    if input_array is not None and input_cnt != 0:
        input_array_addr = ql.os.heap.alloc(input_cnt)
        ql.mem.write(input_array_addr, b''.join(struct.pack("<Q", x) for x in input_array))
        ql.log.debug("Created input array at 0x%x" % input_array_addr)
    else:
        input_array_addr = 0

    if input_struct is not None and input_struct_size != 0:
        input_struct_addr = ql.os.heap.alloc(input_struct_size)
        ql.mem.write(input_struct_addr, bytes(input_struct))
        ql.log.debug("Created input struct at 0x%x" % input_struct_addr)
    else:
        input_struct_addr = 0

    if output_array is not None and output_cnt != 0:
        output_array_addr = ql.os.heap.alloc(output_cnt)
        ql.mem.write(output_array_addr, b''.join(struct.pack("<Q", x) for x in output_array))
        ql.log.debug("Created output array at 0x%x" % output_array_addr)
    else:
        output_array_addr = 0

    if output_struct is not None and output_struct_size != 0:
        output_struct_addr = ql.os.heap.alloc(output_struct_size)
        ql.mem.write(output_struct_addr, bytes(output_struct))
        ql.log.debug("Created output struct at 0x%x" % output_struct_size)
    else:
        output_struct_addr = 0

    dispatch_addr = ql.os.heap.alloc(ctypes.sizeof(IOExternalMethodDispatch))
    ql.log.debug("Created IOExternalMethodDispatch object at 0x%x" % dispatch_addr)
    dispatch_obj = IOExternalMethodDispatch(ql, dispatch_addr)

    args_obj.___reservedA = 0
    args_obj._version = 2
    args_obj._selector = selector
    args_obj._asyncWakePort = 0
    args_obj._asyncReference = POINTER64(0)
    args_obj._asyncReferenceCount = 0
    args_obj._structureVariableOutputData = POINTER64(0)
    args_obj._scalarInput = POINTER64(input_array_addr)
    args_obj._scalarInputCount = input_cnt
    args_obj._structureInput = POINTER64(input_struct_addr)
    args_obj._structureInputSize = input_struct_size

    # https://stackoverflow.com/questions/45432476/sending-iokit-command-with-dynamic-length
    args_obj._structureInputDescriptor = POINTER64(0)
    args_obj._structureOutputDescriptor = POINTER64(0)
    args_obj._structureOutputDescriptorSize = 0

    args_obj._scalarOutput = POINTER64(output_array_addr)
    args_obj._scalarOutputCount = output_cnt
    args_obj._structureOutput = POINTER64(output_struct_addr)
    args_obj._structureOutputSize = output_struct_size

    args_obj.updateToMem()
    ql.log.debug("Initialized IOExternalMethodArguments object")
    ql.os.savedrip=0xffffff8000a106ba
    ql.run(begin=ql.loader.user_alloc)
    ql.os.user_object = ql.reg.rax
    ql.log.debug("Created user object at 0x%x" % ql.os.user_object)

    ql.reg.rdi = ql.os.user_object
    ql.reg.rsi = 0x1337 # owningTask
    ql.reg.rdx = 0 # securityID
    ql.reg.rcx = 0 # type
    ql.reg.r8 = 0 # properties
    ql.stack_push(0)
    ql.os.savedrip=0xffffff8000a10728
    ql.run(begin=ql.loader.user_initWithTask)
    ql.log.debug("Initialized user object")

    # TODO: Add some extra methods with correct order

    ql.reg.rdi = ql.os.user_object
    ql.reg.rsi = selector
    ql.reg.rdx = args_addr
    ql.reg.rcx = dispatch_addr
    ql.reg.r8 = ql.os.kext_object
    ql.reg.r9 = 0
    ql.os.savedrip=0xffffff8000a6e9c7
    ql.run(begin=ql.loader.user_externalMethod)

    args_obj.loadFromMem()
    output_array = args_obj.scalarOutput
    ql.log.debug("Finish IOConnectCallMethod")
    return args_obj.scalarOutput, type(output_struct).from_buffer(args_obj.structureOutput)


def gen_stub_code(ql, params, func, ret=0):
    """
    stub:
        0:  48 bf aa aa aa aa aa    movabs rdi,0xaaaaaaaaaaaaaaaa
        7:  aa aa aa
        a:  48 be bb bb bb bb bb    movabs rsi,0xbbbbbbbbbbbbbbbb
        11: bb bb bb
        14: 48 ba cc cc cc cc cc    movabs rdx,0xcccccccccccccccc
        1b: cc cc cc
        1e: 48 b9 dd dd dd dd dd    movabs rcx,0xdddddddddddddddd
        25: dd dd dd
        28: 49 b8 ee ee ee ee ee    movabs r8,0xeeeeeeeeeeeeeeee
        2f: ee ee ee
        32: 49 b9 22 22 22 22 22    movabs r9,0x2222222222222222
        39: 22 22 22
        3c: 48 b8 11 11 11 11 11    movabs rax,0x1111111111111111
        43: 11 11 11
        46: ff e0                   jmp    rax
    """
    reg_list = [b"\x48\xbf", b"\x48\xbe", b"\x48\xba", b"\x48\xb9", b"\x49\xb8", b"\x49\xb9"]
    remains = 0
    shellcode = b""
    if len(params) <= 6:
        for idx, p in enumerate(params):
            shellcode += reg_list[idx] + struct.pack("<Q", p)
    else:
        for idx, p in enumerate(params[:6]):
            shellcode += reg_list[idx] + struct.pack("<Q", p)
        remains = len(params) - 6
        for i in range(remains):
            shellcode += b"\x48\xb8" + struct.pack("<Q", params[i + 6]) + b"\x50"

    clean_stack = b""
    if remains > 0:
        """
        clean_stack:
            0:  48 81 c4 ff ff 00 00    add    rsp,0xffff
            7:  c3                      ret
        """
        clean_stack = b"\x48\x81\xc4" + struct.pack("<H", remains * 8) + b"\x00\x00\xc3"
    else:
        """
        clean_stack:
            0:  c3                      ret
        """
        clean_stack = b"\xc3"

    cleaner = ql.os.heap.alloc(len(clean_stack))
    ql.mem.write(cleaner, clean_stack)

    if func > 0:
        shellcode += b"\x48\xb8" + struct.pack("<Q", cleaner) + b"\x50"
        shellcode += b"\x48\xb8" + struct.pack("<Q", func)
        shellcode += b"\xff\xe0"
    else:
        shellcode = b"\x48\xb8" + struct.pack("<Q", ret) + b"\xc3"

    trampoline = ql.os.heap.alloc(len(shellcode))
    ql.mem.write(trampoline, shellcode)
    return trampoline

def env_dict_to_array(env_dict):
    env_list = []
    for item in env_dict:
        env_list.append(item + "=" + env_dict[item])
    return env_list


def page_align_end(addr, page_size):
    if addr % page_size == 0:
        return addr
    else:
        return int(((addr / page_size) + 1) * page_size)


def set_eflags_cf(ql, target_cf):
    ql.reg.ef = ( ql.reg.ef & 0xfffffffe ) | target_cf
    return ql.reg.ef
