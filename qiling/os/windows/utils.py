#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from typing import Iterable, Tuple, TypeVar

from unicorn import UcError

from qiling import Qiling
from qiling.const import QL_OS
from qiling.os.const import POINTER
from qiling.os.windows.fncc import STDCALL
from qiling.os.windows.wdk_const import *
from qiling.os.windows.structs import *
from qiling.utils import verify_ret

Comparable = TypeVar('Comparable', str, int)

# an alternative to Python2 cmp builtin which no longer exists in Python3
def cmp(a: Comparable, b: Comparable) -> int:
    return (a > b) - (a < b)


def has_lib_ext(name: str) -> bool:
    ext = name.lower().rpartition('.')[-1]

    return ext in ("dll", "exe", "sys", "drv")


def io_Write(ql: Qiling, in_buffer: bytes):
    heap = ql.os.heap

    if ql.loader.driver_object.MajorFunction[IRP_MJ_WRITE] == 0:
        # raise error?
        return (False, None)

    driver_object_cls = ql.loader.driver_object.__class__
    buf = ql.mem.read(ql.loader.driver_object.DeviceObject, ctypes.sizeof(driver_object_cls))
    device_object = driver_object_cls.from_buffer(buf)

    alloc_addr = []
    def build_mdl(buffer_size: int, data=None):
        mdl = make_mdl(ql.arch.bits)

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
    irp = make_irp(ql.arch.bits)
    irpstack_class = irp.irpstack._type_

    irp_addr = heap.alloc(ctypes.sizeof(irp))
    alloc_addr.append(irp_addr)

    irpstack_addr = heap.alloc(ctypes.sizeof(irpstack_class))
    alloc_addr.append(irpstack_addr)

    # setup irp stack parameters
    irpstack = irpstack_class()
    # setup IRP structure
    irp.irpstack = ctypes.cast(irpstack_addr, ctypes.POINTER(irpstack_class))

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
        mdl_addr = heap.alloc(ctypes.sizeof(mdl))
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
    ql.os.fcall.writeParams((
        (POINTER, ql.loader.driver_object.DeviceObject),
        (POINTER, irp_addr)
    ))

    try:
        # now emulate 
        ql.run(ql.loader.driver_object.MajorFunction[IRP_MJ_WRITE])
    except UcError as err:
        verify_ret(ql, err)

    # read current IRP state
    irp_buffer = ql.mem.read(irp_addr, ctypes.sizeof(irp))
    irp = irp.from_buffer(irp_buffer)

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

    allocations = []

    def __heap_alloc(size: int) -> int:
        address = ql.os.heap.alloc(size)
        allocations.append(address)

        return address

    def __free_all(allocations: Iterable[int]) -> None:
        for address in allocations:
            ql.os.heap.free(address)

    def ioctl_code(DeviceType: int, Function: int, Method: int, Access: int) -> int:
        return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

    def build_mdl(buffer_size, data=None):
        mdl = make_mdl(ql.arch.bits)

        mapped_address = __heap_alloc(buffer_size)
        mdl.MappedSystemVa.value = mapped_address
        mdl.StartVa.value = mapped_address
        mdl.ByteOffset = 0
        mdl.ByteCount = buffer_size

        if data:
            written = data if len(data) <= buffer_size else data[:buffer_size]
            ql.mem.write(mapped_address, written)

        return mdl

    if ql.loader.driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL] == 0:
        # raise error?
        return (None, None, None)

    # create new memory region to store input data
    _ioctl_code, output_buffer_size, in_buffer = params
    # extract data transfer method
    devicetype, function, ctl_method, access = _ioctl_code

    input_buffer_size = len(in_buffer)
    input_buffer_addr = __heap_alloc(input_buffer_size)
    ql.mem.write(input_buffer_addr, bytes(in_buffer))

    # create new memory region to store out data
    output_buffer_addr = __heap_alloc(output_buffer_size)

    # allocate memory regions for IRP and IO_STACK_LOCATION
    irp = make_irp(ql.arch.bits)
    irpstack_class = irp.irpstack._type_

    irp_addr = __heap_alloc(ctypes.sizeof(irp))
    irpstack_addr = __heap_alloc(ctypes.sizeof(irpstack_class))

    # setup irp stack parameters
    irpstack = irpstack_class()
    # setup IRP structure
    irp.irpstack = ctypes.cast(irpstack_addr, ctypes.POINTER(irpstack_class))

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
    system_buffer_addr = __heap_alloc(system_buffer_size)

    # init data from input buffer
    ql.mem.write(system_buffer_addr, bytes(in_buffer))
    irp.AssociatedIrp.SystemBuffer.value = system_buffer_addr

    if ctl_method in (METHOD_IN_DIRECT, METHOD_OUT_DIRECT):
        # Create MDL structure for output data
        # used by both IOCTL_METHOD_IN_DIRECT and IOCTL_METHOD_OUT_DIRECT
        mdl = build_mdl(output_buffer_size)
        mdl_addr = __heap_alloc(ctypes.sizeof(mdl))

        ql.mem.write(mdl_addr, bytes(mdl))
        irp.MdlAddress.value = mdl_addr

    # everything is done! Write IRP to memory
    ql.mem.write(irp_addr, bytes(irp))

    # set function args
    ql.log.info("Executing IOCTL with DeviceObject = 0x%x, IRP = 0x%x" %(ql.loader.driver_object.DeviceObject, irp_addr))
    # TODO: make sure this is indeed STDCALL
    ql.os.fcall = ql.os.fcall_select(STDCALL)
    ql.os.fcall.writeParams((
        (POINTER, ql.loader.driver_object.DeviceObject),
        (POINTER, irp_addr)
    ))

    try:
        ql.log.info(f"Executing from: {ql.loader.driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL]:#x}")
        # now emulate IOCTL's DeviceControl
        ql.run(ql.loader.driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL])
    except UcError as err:
        verify_ret(ql, err)

    # read current IRP state
    irp_buffer = ql.mem.read(irp_addr, ctypes.sizeof(irp))
    irp = irp.__class__.from_buffer(irp_buffer)

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
    __free_all(allocations)

    return io_status.Status.Status, io_status.Information.value, output_data
