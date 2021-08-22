#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
import ntpath
from typing import Tuple, TypeVar

from unicorn import UcError

from qiling import Qiling
from qiling.os.const import POINTER
from qiling.os.windows.fncc import STDCALL
from qiling.os.windows.wdk_const import *
from qiling.os.windows.structs import *
from qiling.utils import verify_ret

Comparable = TypeVar('Comparable', str, int)

# an alternative to Python2 cmp builtin which no longer exists in Python3
def cmp(a: Comparable, b: Comparable) -> int:
    return (a > b) - (a < b)

def ql_x86_windows_hook_mem_error(ql: Qiling, access, addr: int, size: int, value: int):
    ql.log.debug(f'ERROR: unmapped memory access at {addr:#x}')
    return False


def is_file_library(string: str) -> bool:
    string = string.lower()
    extension = string.rpartition('.')[-1]
    return extension in ("dll", "exe", "sys", "drv")


def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

# FIXME: determining a function size by locating 'ret' opcodes in its code is a very unreliable way, to say
# the least. not only that 'ret' instructions may appear more than once in a single function, they not are
# necessarily located at the last function basic block: think of a typical nested loop spaghetty.
#
# also, there is no telling whether a 0xC3 value found in function code is actually a 'ret' instruction, or
# just part of a magic value (e.g. "mov eax, 0xffffffc3").
#
# finally, if this method happens to find the correct function size, by any chance, that would be a pure luck.
def find_size_function(ql: Qiling, func_addr: int):
    # We have to retrieve the return address position
    code = ql.mem.read(func_addr, 0x100)
    return_procedures = [b"\xc3", b"\xc2", b"\xcb", b"\xca"]
    min_index = min([code.index(return_value) for return_value in return_procedures if return_value in code])
    return min_index


def io_Write(ql: Qiling, in_buffer: bytes):
    heap = ql.os.heap

    if ql.ostype == QL_OS.WINDOWS:

        if ql.loader.driver_object.MajorFunction[IRP_MJ_WRITE] == 0:
            # raise error?
            return (False, None)

    if ql.archbit == 32:
        buf = ql.mem.read(ql.loader.driver_object.DeviceObject, ctypes.sizeof(DEVICE_OBJECT32))
        device_object = DEVICE_OBJECT32.from_buffer(buf)
    else:
        buf = ql.mem.read(ql.loader.driver_object.DeviceObject, ctypes.sizeof(DEVICE_OBJECT64))
        device_object = DEVICE_OBJECT64.from_buffer(buf)

    alloc_addr = []
    def build_mdl(buffer_size, data=None):
        if ql.archtype == QL_ARCH.X8664:
            mdl = MDL64()
        else:
            mdl = MDL32()

        mapped_address = heap.alloc(buffer_size)
        alloc_addr.append(mapped_address)
        mdl.MappedSystemVa.value = mapped_address
        mdl.StartVa.value = mapped_address
        mdl.ByteOffset = 0
        mdl.ByteCount = buffer_size
        if data:
            written = data if len(data) <= buffer_size else data[:buffer_size]
            ql.mem.write(mapped_address, written)

        return mdl
    # allocate memory regions for IRP and IO_STACK_LOCATION
    if ql.archtype == QL_ARCH.X8664:
        irp_addr = heap.alloc(ctypes.sizeof(IRP64))
        alloc_addr.append(irp_addr)
        irpstack_addr = heap.alloc(ctypes.sizeof(IO_STACK_LOCATION64))
        alloc_addr.append(irpstack_addr)
        # setup irp stack parameters
        irpstack = IO_STACK_LOCATION64()
        # setup IRP structure
        irp = IRP64()
        irp.irpstack = ctypes.cast(irpstack_addr, ctypes.POINTER(IO_STACK_LOCATION64))
    else:
        irp_addr = heap.alloc(ctypes.sizeof(IRP32))
        alloc_addr.append(irp_addr)
        irpstack_addr = heap.alloc(ctypes.sizeof(IO_STACK_LOCATION32))
        alloc_addr.append(irpstack_addr)
        # setup irp stack parameters
        irpstack = IO_STACK_LOCATION32()
        # setup IRP structure
        irp = IRP32()
        irp.irpstack = ctypes.cast(irpstack_addr, ctypes.POINTER(IO_STACK_LOCATION32))

    irpstack.MajorFunction = IRP_MJ_WRITE
    irpstack.Parameters.Write.Length = len(in_buffer)
    ql.mem.write(irpstack_addr, bytes(irpstack))

    if device_object.Flags & DO_BUFFERED_IO:
        # BUFFERED_IO
        system_buffer_addr = heap.alloc(len(in_buffer))
        alloc_addr.append(system_buffer_addr)
        ql.mem.write(system_buffer_addr, bytes(in_buffer))
        irp.AssociatedIrp.SystemBuffer.value = system_buffer_addr
    elif device_object.Flags & DO_DIRECT_IO:
        # DIRECT_IO
        mdl = build_mdl(len(in_buffer))
        if ql.archtype == QL_ARCH.X8664:
            mdl_addr = heap.alloc(ctypes.sizeof(MDL64))
        else:
            mdl_addr = heap.alloc(ctypes.sizeof(MDL32))

        alloc_addr.append(mdl_addr)

        ql.mem.write(mdl_addr, bytes(mdl))
        irp.MdlAddress.value = mdl_addr
    else:
        # NEITHER_IO
        input_buffer_size = len(in_buffer)
        input_buffer_addr = heap.alloc(input_buffer_size)
        alloc_addr.append(input_buffer_addr)
        ql.mem.write(input_buffer_addr, bytes(in_buffer))
        irp.UserBuffer.value = input_buffer_addr

    # everything is done! Write IRP to memory
    ql.mem.write(irp_addr, bytes(irp))

    # set function args
    # TODO: make sure this is indeed STDCALL
    ql.os.fcall = ql.os.fcall_select(STDCALL)
    ql.os.fcall.writeParams(((POINTER, ql.loader.driver_object.DeviceObject), (POINTER, irp_addr)))

    try:
        # now emulate 
        ql.run(ql.loader.driver_object.MajorFunction[IRP_MJ_WRITE])
    except UcError as err:
        verify_ret(ql, err)

    # read current IRP state
    if ql.archtype == QL_ARCH.X8664:
        irp_buffer = ql.mem.read(irp_addr, ctypes.sizeof(IRP64))
        irp = IRP64.from_buffer(irp_buffer)
    else:
        irp_buffer = ql.mem.read(irp_addr, ctypes.sizeof(IRP32))
        irp = IRP32.from_buffer(irp_buffer)

    io_status = irp.IoStatus
    # now free all alloc memory
    for addr in alloc_addr:
        # print("freeing heap memory at 0x%x" %addr) # FIXME: the output is not deterministic??
        heap.free(addr)

    return True, io_status.Information.value

# Emulate DeviceIoControl() of Windows
# BOOL DeviceIoControl(
#      HANDLE       hDevice,
#      DWORD        dwIoControlCode,
#      LPVOID       lpInBuffer,
#      DWORD        nInBufferSize,
#      LPVOID       lpOutBuffer,
#      DWORD        nOutBufferSize,
#      LPDWORD      lpBytesReturned,
#      LPOVERLAPPED lpOverlapped);
def ioctl(ql: Qiling, params: Tuple[Tuple, int, bytes]) -> Tuple:
    heap = ql.os.heap

    def ioctl_code(DeviceType, Function, Method, Access):
        return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

    alloc_addr = []
    def build_mdl(buffer_size, data=None):
        if ql.archtype == QL_ARCH.X8664:
            mdl = MDL64()
        else:
            mdl = MDL32()

        mapped_address = heap.alloc(buffer_size)
        alloc_addr.append(mapped_address)
        mdl.MappedSystemVa.value = mapped_address
        mdl.StartVa.value = mapped_address
        mdl.ByteOffset = 0
        mdl.ByteCount = buffer_size
        if data:
            written = data if len(data) <= buffer_size else data[:buffer_size]
            ql.mem.write(mapped_address, written)

        return mdl

    # quick simple way to manage all alloc memory
    if ql.ostype == QL_OS.WINDOWS:
        # print("DeviceControl callback is at 0x%x" % ql.loader.driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL])
        if ql.loader.driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL] == 0:
            # raise error?
            return (None, None, None)

        # create new memory region to store input data
        _ioctl_code, output_buffer_size, in_buffer = params
        # extract data transfer method
        devicetype, function, ctl_method, access = _ioctl_code

        input_buffer_size = len(in_buffer)
        input_buffer_addr = heap.alloc(input_buffer_size)
        alloc_addr.append(input_buffer_addr)
        ql.mem.write(input_buffer_addr, bytes(in_buffer))

        # create new memory region to store out data
        output_buffer_addr = heap.alloc(output_buffer_size)
        alloc_addr.append(output_buffer_addr)

        # allocate memory regions for IRP and IO_STACK_LOCATION
        if ql.archtype == QL_ARCH.X8664:
            irp_addr = heap.alloc(ctypes.sizeof(IRP64))
            alloc_addr.append(irp_addr)
            irpstack_addr = heap.alloc(ctypes.sizeof(IO_STACK_LOCATION64))
            alloc_addr.append(irpstack_addr)
            # setup irp stack parameters
            irpstack = IO_STACK_LOCATION64()
            # setup IRP structure
            irp = IRP64()
            irp.irpstack = ctypes.cast(irpstack_addr, ctypes.POINTER(IO_STACK_LOCATION64))
        else:
            irp_addr = heap.alloc(ctypes.sizeof(IRP32))
            alloc_addr.append(irp_addr)
            irpstack_addr = heap.alloc(ctypes.sizeof(IO_STACK_LOCATION32))
            alloc_addr.append(irpstack_addr)
            # setup irp stack parameters
            irpstack = IO_STACK_LOCATION32()
            # setup IRP structure
            irp = IRP32()
            irp.irpstack = ctypes.cast(irpstack_addr, ctypes.POINTER(IO_STACK_LOCATION32))

            #print("32 stack location size = 0x%x" %ctypes.sizeof(IO_STACK_LOCATION32))
            #print("32 status block size = 0x%x" %ctypes.sizeof(IO_STATUS_BLOCK32))
            #print("32 irp size = 0x%x" %ctypes.sizeof(IRP32))
            #print("32 IoStatus offset = 0x%x" %IRP32.IoStatus.offset)
            #print("32 UserIosb offset = 0x%x" %IRP32.UserIosb.offset)
            #print("32 UserEvent offset = 0x%x" %IRP32.UserEvent.offset)
            #print("32 UserBuffer offset = 0x%x" %IRP32.UserBuffer.offset)
            #print("32 irpstack offset = 0x%x" %IRP32.irpstack.offset)
            #print("irp at %x, irpstack at %x" %(irp_addr, irpstack_addr))

        ql.log.info("IRP is at 0x%x, IO_STACK_LOCATION is at 0x%x" %(irp_addr, irpstack_addr))

        irpstack.Parameters.DeviceIoControl.IoControlCode = ioctl_code(devicetype, function, ctl_method, access)
        irpstack.Parameters.DeviceIoControl.OutputBufferLength = output_buffer_size
        irpstack.Parameters.DeviceIoControl.InputBufferLength = input_buffer_size
        irpstack.Parameters.DeviceIoControl.Type3InputBuffer.value = input_buffer_addr # used by IOCTL_METHOD_NEITHER
        ql.mem.write(irpstack_addr, bytes(irpstack))

        if ctl_method == METHOD_NEITHER:
            irp.UserBuffer.value = output_buffer_addr  # used by IOCTL_METHOD_NEITHER

        # allocate memory for AssociatedIrp.SystemBuffer
        # used by IOCTL_METHOD_IN_DIRECT, IOCTL_METHOD_OUT_DIRECT and IOCTL_METHOD_BUFFERED
        system_buffer_size = max(input_buffer_size, output_buffer_size)
        system_buffer_addr = heap.alloc(system_buffer_size)
        alloc_addr.append(system_buffer_addr)

        # init data from input buffer
        ql.mem.write(system_buffer_addr, bytes(in_buffer))
        irp.AssociatedIrp.SystemBuffer.value = system_buffer_addr

        if ctl_method in (METHOD_IN_DIRECT, METHOD_OUT_DIRECT):
            # Create MDL structure for output data
            # used by both IOCTL_METHOD_IN_DIRECT and IOCTL_METHOD_OUT_DIRECT
            mdl = build_mdl(output_buffer_size)
            if ql.archtype == QL_ARCH.X8664:
                mdl_addr = heap.alloc(ctypes.sizeof(MDL64))
            else:
                mdl_addr = heap.alloc(ctypes.sizeof(MDL32))

            alloc_addr.append(mdl_addr)

            ql.mem.write(mdl_addr, bytes(mdl))
            irp.MdlAddress.value = mdl_addr

        # everything is done! Write IRP to memory
        ql.mem.write(irp_addr, bytes(irp))

        # set function args
        ql.log.info("Executing IOCTL with DeviceObject = 0x%x, IRP = 0x%x" %(ql.loader.driver_object.DeviceObject, irp_addr))
        # TODO: make sure this is indeed STDCALL
        ql.os.fcall = ql.os.fcall_select(STDCALL)
        ql.os.fcall.writeParams(((POINTER, ql.loader.driver_object.DeviceObject), (POINTER, irp_addr)))

        try:
            # now emulate IOCTL's DeviceControl
            ql.run(ql.loader.driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL])
        except UcError as err:
            verify_ret(ql, err)

        # read current IRP state
        if ql.archtype == QL_ARCH.X8664:
            irp_buffer = ql.mem.read(irp_addr, ctypes.sizeof(IRP64))
            irp = IRP64.from_buffer(irp_buffer)
        else:
            irp_buffer = ql.mem.read(irp_addr, ctypes.sizeof(IRP32))
            irp = IRP32.from_buffer(irp_buffer)

        io_status = irp.IoStatus

        # read output data
        output_data = b''
        if io_status.Status.Status >= 0:
            if ctl_method == METHOD_BUFFERED:
                output_data = ql.mem.read(system_buffer_addr, io_status.Information.value)
            if ctl_method in (METHOD_IN_DIRECT, METHOD_OUT_DIRECT):
                output_data = ql.mem.read(mdl.MappedSystemVa.value, io_status.Information.value)
            if ctl_method == METHOD_NEITHER:
                output_data = ql.mem.read(output_buffer_addr, io_status.Information.value)

        # now free all alloc memory
        for addr in alloc_addr:
            # print("freeing heap memory at 0x%x" %addr) # FIXME: the output is not deterministic??
            heap.free(addr)
        #print("\n")

        return io_status.Status.Status, io_status.Information.value, output_data
    else: # TODO: IOCTL for non-Windows.
        raise NotImplementedError
