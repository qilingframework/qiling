#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Iterable, Optional, Tuple, TypeVar

from unicorn import UcError

from qiling import Qiling
from qiling.exception import QlErrorSyscallError
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


def io_Write(ql: Qiling, in_buffer: bytes) -> int:
    major_func = ql.loader.driver_object.MajorFunction[IRP_MJ_WRITE]

    if not major_func:
        raise QlErrorSyscallError('null MajorFunction field')

    # keep track of all heap allocation within this scope to be able
    # to free them when done
    allocations = []

    def __heap_alloc(size: int) -> int:
        address = ql.os.heap.alloc(size)
        allocations.append(address)

        return address

    def __free_all(allocations: Iterable[int]) -> None:
        for address in allocations:
            ql.os.heap.free(address)

    # allocate memory for IRP
    irp_struct = make_irp(ql.arch.bits)
    irp_addr = __heap_alloc(irp_struct.sizeof())
    ql.log.info(f'IRP is at {irp_addr:#x}')

    # populate the structure
    with irp_struct.ref(ql.mem, irp_addr) as irp_obj:

        # allocate memory for IO_STACK_LOCATION
        irpstack_struct = make_io_stack_location(ql.arch.bits)
        irpstack_addr = __heap_alloc(irpstack_struct.sizeof())
        ql.log.info(f'IO_STACK_LOCATION is at {irpstack_addr:#x}')

        # populate the structure
        with irpstack_struct.ref(ql.mem, irpstack_addr) as irpstack_obj:
            irpstack_obj.MajorFunction = IRP_MJ_WRITE
            irpstack_obj.Parameters.Write.Length = len(in_buffer)

        # load DeviceObject from memory
        drvobj_struct = ql.loader.driver_object.__class__
        devobj_obj = drvobj_struct.load_from(ql.loader.driver_object.DeviceObject)

        # BUFFERED_IO
        if devobj_obj.Flags & DO_BUFFERED_IO:
            system_buffer_addr = __heap_alloc(len(in_buffer))

            ql.mem.write(system_buffer_addr, bytes(in_buffer))
            irp_obj.AssociatedIrp.SystemBuffer = system_buffer_addr

        # DIRECT_IO
        elif devobj_obj.Flags & DO_DIRECT_IO:
            mdl_struct = make_mdl(ql.arch.bits)
            mdl_addr = __heap_alloc(mdl_struct.sizeof())

            with mdl_struct.ref(ql.mem, mdl_addr) as mdl_obj:
                mapped_address = __heap_alloc(len(in_buffer))

                mdl_obj.MappedSystemVa = mapped_address
                mdl_obj.StartVa = mapped_address
                mdl_obj.ByteOffset = 0
                mdl_obj.ByteCount = len(in_buffer)

            irp_obj.MdlAddress = mdl_addr

        # NEITHER_IO
        else:
            input_buffer_addr = __heap_alloc(len(in_buffer))

            ql.mem.write(input_buffer_addr, bytes(in_buffer))
            irp_obj.UserBuffer = input_buffer_addr

    # set function args
    # TODO: make sure this is indeed STDCALL
    ql.os.fcall = ql.os.fcall_select(STDCALL)
    ql.os.fcall.writeParams((
        (POINTER, ql.loader.driver_object.DeviceObject),
        (POINTER, irp_addr)
    ))

    ql.log.info(f'Executing from {major_func:#x}')

    try:
        # now emulate
        ql.run(major_func)
    except UcError as err:
        verify_ret(ql, err)

    # read updated IRP state before releasing resources
    with irp_struct.ref(ql.mem, irp_addr) as irp_obj:
        info = irp_obj.IoStatus.Information

    # free all allocated memory
    __free_all(allocations)

    return info


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
def ioctl(ql: Qiling, params: Tuple[Tuple, int, bytes]) -> Tuple[int, int, bytes]:
    major_func = ql.loader.driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL]

    if not major_func:
        raise QlErrorSyscallError('null MajorFunction field')

    # keep track of all heap allocation within this scope to be able
    # to free them when done
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

    # create new memory region to store input data
    _ioctl_code, output_buffer_size, in_buffer = params

    # extract data transfer method
    devicetype, function, ctl_method, access = _ioctl_code

    input_buffer_size = len(in_buffer)
    input_buffer_addr = __heap_alloc(input_buffer_size)
    ql.mem.write(input_buffer_addr, bytes(in_buffer))

    # create new memory region to store out data
    output_buffer_addr = __heap_alloc(output_buffer_size)

    # allocate memory for AssociatedIrp.SystemBuffer
    # used by IOCTL_METHOD_IN_DIRECT, IOCTL_METHOD_OUT_DIRECT and IOCTL_METHOD_BUFFERED
    system_buffer_size = max(input_buffer_size, output_buffer_size)
    system_buffer_addr = __heap_alloc(system_buffer_size)
    ql.mem.write(system_buffer_addr, bytes(in_buffer))

    # allocate memory for IRP
    irp_struct = make_irp(ql.arch.bits)
    irp_addr = __heap_alloc(irp_struct.sizeof())
    ql.log.info(f'IRP is at {irp_addr:#x}')

    # populate the structure
    with irp_struct.ref(ql.mem, irp_addr) as irp_obj:

        # allocate memory for IO_STACK_LOCATION
        irpstack_struct = make_io_stack_location(ql.arch.bits)
        irpstack_addr = __heap_alloc(irpstack_struct.sizeof())
        ql.log.info(f'IO_STACK_LOCATION is at {irpstack_addr:#x}')

        # populate the structure
        with irpstack_struct.ref(ql.mem, irpstack_addr) as irpstack_obj:
            irpstack_obj.Parameters.DeviceIoControl.IoControlCode = ioctl_code(devicetype, function, ctl_method, access)
            irpstack_obj.Parameters.DeviceIoControl.OutputBufferLength = output_buffer_size
            irpstack_obj.Parameters.DeviceIoControl.InputBufferLength = input_buffer_size
            irpstack_obj.Parameters.DeviceIoControl.Type3InputBuffer = input_buffer_addr # used by IOCTL_METHOD_NEITHER

        irp_obj.irpstack = irpstack_addr

        if ctl_method in (METHOD_IN_DIRECT, METHOD_OUT_DIRECT):
            mdl_struct = make_mdl(ql.arch.bits)
            mdl_addr = __heap_alloc(mdl_struct.sizeof())

            # Create MDL structure for output data
            with mdl_struct.ref(ql.mem, mdl_addr) as mdl_obj:
                mapped_address = __heap_alloc(output_buffer_size)

                mdl_obj.MappedSystemVa = mapped_address
                mdl_obj.StartVa = mapped_address
                mdl_obj.ByteOffset = 0
                mdl_obj.ByteCount = output_buffer_size

            # used by both IOCTL_METHOD_IN_DIRECT and IOCTL_METHOD_OUT_DIRECT
            irp_obj.MdlAddress = mdl_addr

        elif ctl_method == METHOD_NEITHER:
            # used by IOCTL_METHOD_NEITHER
            irp_obj.UserBuffer = output_buffer_addr

        irp_obj.AssociatedIrp.SystemBuffer = system_buffer_addr

    # set function args
    # TODO: make sure this is indeed STDCALL
    ql.os.fcall = ql.os.fcall_select(STDCALL)
    ql.os.fcall.writeParams((
        (POINTER, ql.loader.driver_object.DeviceObject),
        (POINTER, irp_addr)
    ))

    ql.log.info(f'Executing from {major_func:#x}')

    try:
        # now emulate IOCTL's DeviceControl
        ql.run(major_func)
    except UcError as err:
        verify_ret(ql, err)

    # read updated IRP state before releasing resources
    with irp_struct.ref(ql.mem, irp_addr) as irp_obj:
        io_status = irp_obj.IoStatus
        mdl_addr = irp_obj.MdlAddress

        info = io_status.Information
        status = io_status.Status.Status

    # read output data
    output_data = b''

    if status >= 0:
        if ctl_method == METHOD_BUFFERED:
            output_data = ql.mem.read(system_buffer_addr, info)

        elif ctl_method in (METHOD_IN_DIRECT, METHOD_OUT_DIRECT):
            with mdl_struct.ref(ql.mem, mdl_addr) as mdl_obj:
                mapped_va = mdl_obj.MappedSystemVa

            output_data = ql.mem.read(mapped_va, info)

        elif ctl_method == METHOD_NEITHER:
            output_data = ql.mem.read(output_buffer_addr, info)

    # now free all alloc memory
    __free_all(allocations)

    return status, info, output_data


def read_pansi_string(ql: Qiling, ptr: int) -> Optional[str]:
    """Read and decode the string referenced by a PANSI_STRING structure. It is
    the caller responsibility to make sure the pointer to the structure is accesible.
    """

    astr_obj = make_ansi_string(ql.arch.bits).load_from(ql.mem, ptr)

    if astr_obj.Buffer and astr_obj.Length:
        return ql.os.utils.read_cstring(astr_obj.Buffer, maxlen=astr_obj.Length)

    return None


def read_punicode_string(ql: Qiling, ptr: int) -> Optional[str]:
    """Read and decode the string referenced by a PUNICODE_STRING structure. It is
    the caller responsibility to make sure the pointer to the structure is accesible.
    """

    ucstr_obj = make_unicode_string(ql.arch.bits).load_from(ql.mem, ptr)

    if ucstr_obj.Buffer and ucstr_obj.Length:
        assert ucstr_obj.Length % 2 == 0, f'wide string size is expected to be a multiplication of 2. got: {ucstr_obj.Length}'

        return ql.os.utils.read_wstring(ucstr_obj.Buffer, maxlen=ucstr_obj.Length // 2)

    return None
