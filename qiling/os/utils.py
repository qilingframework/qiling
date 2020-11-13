#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

"""
This module is intended for general purpose functions that are only used in qiling.os
"""

import ctypes, inspect, os, struct, uuid

from json import dumps
from pathlib import Path, PurePosixPath, PureWindowsPath, PosixPath, WindowsPath
from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

from capstone import *
from capstone.arm_const import *
from capstone.x86_const import *
from capstone.arm64_const import *
from capstone.mips_const import *
from keystone import *

from qiling.const import *
from qiling.exception import *
from .const import *

from qiling.os.windows.wdk_const import *
from qiling.os.windows.structs import *
from qiling.utils import verify_ret

# OH-MY-WIN32 !!!
# Some codes from cygwin.
class PathUtils:

    # Basic guide:
    #     We should only handle "normal" paths like "C:\Windows\System32" and "bin/a.exe" for users.
    #     For UNC paths like '\\.\PHYSICALDRIVE0" and "\\Server\Share", they should be implemented 
    #     by users via fs mapping interface.
    @staticmethod
    def convert_win32_to_posix(rootfs, cwd, path):
        # rootfs is a concrete path.
        rootfs = Path(rootfs)
        # cwd and path are pure paths
        cwd = PurePosixPath(cwd[1:])

        result = None
        # Things are complicated here.
        # See https://docs.microsoft.com/zh-cn/windows/win32/fileio/naming-a-file?redirectedfrom=MSDN
        if PureWindowsPath(path).is_absolute():
            if (len(path) >= 2 and path[0] == '\\' and path[1] == '\\') or \
                (len(path) >= 3 and path[0].isalpha() and path[2] == '\\'): # \\.\PhysicalDrive0 or \\Server\Share\Directory or X:\
                # UNC path should be handled in fs mapping. If not, append it to rootfs directly.
                pw = PureWindowsPath(path)
                result = rootfs / PathUtils.normalize(pw)
            else:
                # code should never reach here.
                result = rootfs / PathUtils.normalize(path)
        else:
            if len(path) >= 3 and path[:3] == r'\\?' or path[:3] == r'\??': # \??\ or \\?\ or \Device\..
                # Similair to \\.\, it should be handled in fs mapping.
                pw = PureWindowsPath(path)
                result = rootfs / PathUtils.normalize(cwd / pw.relative_to(pw.anchor).as_posix())
            else:
                # a normal relative path
                result = rootfs / PathUtils.normalize(cwd / PureWindowsPath(path).as_posix())
        return result


    @staticmethod
    def convert_posix_to_win32(rootfs, cwd, path):
        # rootfs is a concrete path.
        rootfs = Path(rootfs)
        # cwd and path are pure paths
        cwd = PurePosixPath(cwd[1:])
        path = PurePosixPath(path)
        if path.is_absolute():
            return rootfs / PathUtils.normalize(path)
        else:
            return rootfs / PathUtils.normalize(cwd / path)
    
    @staticmethod
    def convert_for_native_os(rootfs, cwd, path):
        rootfs = Path(rootfs)
        cwd = PurePosixPath(cwd[1:])
        path = Path(path)
        if path.is_absolute():
            return rootfs / PathUtils.normalize(path)
        else:
            return rootfs / PathUtils.normalize(cwd / path.as_posix())

    @staticmethod
    def normalize(path):
        if type(path) is PurePosixPath:
            normalized_path = PurePosixPath()
        elif type(path) is PureWindowsPath:
            normalized_path = PureWindowsPath()
        elif type(path) is PosixPath:
            normalized_path = PosixPath()
        elif type(path) is WindowsPath:
            normalized_path = WindowsPath()

        # remove anchor (necessary for Windows UNC paths) and convert to relative path
        if path.is_absolute():
            path = path.relative_to(path.anchor)

        for p in path.parts:
            if p == '.':
                continue

            if p == '..':
                normalized_path = normalized_path.parent
                continue

            normalized_path /= p

        return normalized_path

class QlOsUtils:
    def __init__(self, ql):
        self.ql = ql
        self.archtype = None
        self.ostype = None
        self.path = None
        self.archendian = None
        self.output_ready = False

    def lsbmsb_convert(self, sc, size=4):
        split_bytes = []
        n = size
        for index in range(0, len(sc), n):
            split_bytes.append((sc[index: index + n])[::-1])

        ebsc = b""
        for i in split_bytes:
            ebsc += i

        return ebsc

    def convert_path(self, rootfs, cwd, path):
        if  (self.ql.ostype == self.ql.platform ) \
            or (self.ql.ostype in [QL_OS.LINUX, QL_OS.MACOS] and self.ql.platform in [QL_OS.LINUX, QL_OS.MACOS]):
            return PathUtils.convert_for_native_os(rootfs, cwd, path)
        elif self.ql.ostype in [QL_OS.LINUX, QL_OS.MACOS] and self.ql.platform == QL_OS.WINDOWS:
            return PathUtils.convert_posix_to_win32(rootfs, cwd, path)
        elif self.ql.ostype == QL_OS.WINDOWS and self.ql.platform in [QL_OS.LINUX, QL_OS.MACOS]:
            return PathUtils.convert_win32_to_posix(rootfs, cwd, path)
        else:
            return None
    
    def transform_to_link_path(self, path):
        if self.ql.multithread:
            cur_path = self.ql.os.thread_management.cur_thread.get_current_path()
        else:
            cur_path = self.ql.os.current_path

        # Sanity check.
        if cur_path[0] != '/':
            self.ql.nprint(f"[!] Warning: cur_path doesn't start with a /")
        
        rootfs = self.ql.rootfs
        real_path  = self.convert_path(rootfs, cur_path, path)

        return str(real_path.absolute())

    def transform_to_real_path(self, path):
        from types import FunctionType

        if self.ql.multithread:
            cur_path = self.ql.os.thread_management.cur_thread.get_current_path()
        else:
            cur_path = self.ql.os.current_path

        # Sanity check.
        if cur_path[0] != '/':
            self.ql.nprint(f"[!] Warning: cur_path must start with /")

        rootfs = self.ql.rootfs
        real_path = self.convert_path(rootfs, cur_path, path)
        
        if os.path.islink(real_path):
            link_path = Path(os.readlink(real_path))
            if not link_path.is_absolute():
                real_path = Path(os.path.join(os.path.dirname(real_path), link_path))
            
        return str(real_path.absolute())

    # The `relative path` here refers to the path which is relative to the rootfs.
    def transform_to_relative_path(self, path):
        if self.ql.multithread:
            cur_path = self.ql.os.thread_management.cur_thread.get_current_path()
        else:
            cur_path = self.ql.os.current_path

        return str(Path(cur_path) / path)

    def post_report(self):
        self.ql.dprint(D_RPRT, "[+] Syscalls called")
        for key, values in self.ql.os.syscalls.items():
            self.ql.dprint(D_RPRT, "[-] %s:" % key)
            for value in values:
                self.ql.dprint(D_RPRT, "[-] %s " % str(dumps(value)))
        self.ql.dprint(D_RPRT, "[+] Registries accessed")
        for key, values in self.ql.os.registry_manager.accessed.items():
            self.ql.dprint(D_RPRT, "[-] %s:" % key)
            for value in values:
                self.ql.dprint(D_RPRT, "[-] %s " % str(dumps(value)))
        self.ql.dprint(D_RPRT, "[+] Strings")
        for key, values in self.ql.os.appeared_strings.items():
            val = " ".join([str(word) for word in values])
            self.ql.dprint(D_RPRT, "[-] %s: %s" % (key, val))


    def exec_arbitrary(self, start, end):
        old_sp = self.ql.reg.arch_sp

        # we read where this hook is supposed to return
        ret = self.ql.stack_read(0)

        def restore(ql):
            ql.dprint(D_INFO, f"[+] Executed code from 0x{start:x} to 0x{end:x}")
            # now we can restore the register to be where we were supposed to
            old_hook_addr = ql.reg.arch_pc
            ql.reg.arch_sp = old_sp + (ql.archbit // 8)
            ql.reg.arch_pc = ret
            # we want to execute the code once, not more
            ql.hook_address(lambda q: None, old_hook_addr)

        # we have to set an address to restore the registers
        self.ql.hook_address(restore, end, )
        # we want to rewrite the return address to the function
        self.ql.stack_write(0, start)

    def disassembler(self, ql, address, size):
        tmp = self.ql.mem.read(address, size)

        md = self.ql.create_disassembler()

        insn = md.disasm(tmp, address)
        opsize = int(size)

        self.ql.nprint( ("[+] 0x%x" % (address)).ljust( (self.ql.archbit // 8) + 15), end="")

        temp_str = ""
        for i in tmp:
            temp_str += ("%02x " % i)
        self.ql.nprint(temp_str.ljust(30), end="")

        for i in insn:
            self.ql.nprint("%s %s" % (i.mnemonic, i.op_str))

        if self.ql.output == QL_OUTPUT.DUMP:
            for reg in self.ql.reg.register_mapping:
                if isinstance(reg, str):
                    REG_NAME = reg
                    REG_VAL = self.ql.reg.read(reg)
                    self.ql.dprint(D_INFO, "[-] %s\t:\t 0x%x" % (REG_NAME, REG_VAL))

    def setup_output(self):
        if self.output_ready:
            return
        self.output_ready = True
        def ql_hook_block_disasm(ql, address, size):
            self.ql.nprint("\n[+] Tracing basic block at 0x%x" % (address))

        if self.ql.output in (QL_OUTPUT.DISASM, QL_OUTPUT.DUMP):
            if self.ql.output == QL_OUTPUT.DUMP:
                self.ql.hook_block(ql_hook_block_disasm)
            self.ql.hook_code(self.disassembler)

    def stop(self, stop_event=THREAD_EVENT_EXIT_GROUP_EVENT):
        if self.ql.multithread:
            td = self.thread_management.cur_thread
            td.stop()
            td.stop_event = stop_event
        self.ql.emu_stop()

    def read_guid(self, address):
        result = ""
        raw_guid = self.ql.mem.read(address, 16)
        return uuid.UUID(bytes_le=bytes(raw_guid))


    def string_appearance(self, string):
        strings = string.split(" ")
        for string in strings:
            val = self.appeared_strings.get(string, set())
            val.add(self.syscalls_counter)
            self.appeared_strings[string] = val


    def read_wstring(self, address):
        result = ""
        char = self.ql.mem.read(address, 2)
        while char.decode(errors="ignore") != "\x00\x00":
            address += 2
            result += char.decode(errors="ignore")
            char = self.ql.mem.read(address, 2)
        # We need to remove \x00 inside the string. Compares do not work otherwise
        result = result.replace("\x00", "")
        self.string_appearance(result)
        return result


    def read_cstring(self, address):
        result = ""
        char = self.ql.mem.read(address, 1)
        while char.decode(errors="ignore") != "\x00":
            address += 1
            result += char.decode(errors="ignore")
            char = self.ql.mem.read(address, 1)
        self.string_appearance(result)
        return result


    def print_function(self, address, function_name, params, ret, passthru=False):
        function_name = function_name.replace('hook_', '')
        if function_name in ("__stdio_common_vfprintf", "__stdio_common_vfwprintf", "printf", "wsprintfW", "sprintf"):
            return
        log = '0x%0.2x: %s(' % (address, function_name)
        for each in params:
            value = params[each]
            if isinstance(value, str) or type(value) == bytearray:
                log += '%s = "%s", ' % (each, value)
            elif isinstance(value, tuple):
                # we just need the string, not the address in the log
                log += '%s = "%s", ' % (each, value[1])
            else:
                log += '%s = 0x%x, ' % (each, value)
        log = log.strip(", ")
        log += ')'
        if ret is not None:
            log += ' = 0x%x' % ret

        if passthru:
            log += '(PASSTHRU)'

        if self.ql.output != QL_OUTPUT.DEBUG:
            log = log.partition(" ")[-1]
            self.ql.nprint(log)
        else:
            self.ql.dprint(D_INFO, log)

    def printf(self, address, fmt, params_addr, name, wstring=False):
        count = fmt.count("%")
        params = []
        if count > 0:
            for i in range(count):
                param = self.ql.mem.read(params_addr + i * self.ql.pointersize, self.ql.pointersize)
                params.append(
                    self.ql.unpack(param)
                )

            formats = fmt.split("%")[1:]
            index = 0
            for f in formats:
                if f.startswith("s"):
                    if wstring:
                        params[index] = self.read_wstring(params[index])
                    else:
                        params[index] = self.read_cstring(params[index])
                index += 1

            output = '%s(format = %s' % (name, repr(fmt))
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
            output = '%s(format = %s) = 0x%x' % (name, repr(fmt), len(fmt))
            stdout = fmt
        self.ql.nprint(output)
        self.ql.os.stdout.write(bytes(stdout, 'utf-8'))
        return len(stdout), stdout

    def io_Write(self, in_buffer):
        if self.ql.ostype == QL_OS.WINDOWS:

            if self.ql.loader.driver_object.MajorFunction[IRP_MJ_WRITE] == 0:
                # raise error?
                return (False, None)

        if self.ql.archbit == 32:
            buf = self.ql.mem.read(self.ql.loader.driver_object.DeviceObject, ctypes.sizeof(DEVICE_OBJECT32))
            device_object = DEVICE_OBJECT32.from_buffer(buf)
        else:
            buf = self.ql.mem.read(self.ql.loader.driver_object.DeviceObject, ctypes.sizeof(DEVICE_OBJECT64))
            device_object = DEVICE_OBJECT64.from_buffer(buf)

        alloc_addr = []
        def build_mdl(buffer_size, data=None):
            if self.archtype == QL_ARCH.X8664:
                mdl = MDL64()
            else:
                mdl = MDL32()

            mapped_address = self.heap.alloc(buffer_size)
            alloc_addr.append(mapped_address)
            mdl.MappedSystemVa.value = mapped_address
            mdl.StartVa.value = mapped_address
            mdl.ByteOffset = 0
            mdl.ByteCount = buffer_size
            if data:
                written = data if len(data) <= buffer_size else data[:buffer_size]
                self.ql.mem.write(mapped_address, written)

            return mdl
        # allocate memory regions for IRP and IO_STACK_LOCATION
        if self.ql.archtype == QL_ARCH.X8664:
            irp_addr = self.heap.alloc(ctypes.sizeof(IRP64))
            alloc_addr.append(irp_addr)
            irpstack_addr = self.heap.alloc(ctypes.sizeof(IO_STACK_LOCATION64))
            alloc_addr.append(irpstack_addr)
            # setup irp stack parameters
            irpstack = IO_STACK_LOCATION64()
            # setup IRP structure
            irp = IRP64()
            irp.irpstack = ctypes.cast(irpstack_addr, ctypes.POINTER(IO_STACK_LOCATION64))
        else:
            irp_addr = self.heap.alloc(ctypes.sizeof(IRP32))
            alloc_addr.append(irp_addr)
            irpstack_addr = self.heap.alloc(ctypes.sizeof(IO_STACK_LOCATION32))
            alloc_addr.append(irpstack_addr)
            # setup irp stack parameters
            irpstack = IO_STACK_LOCATION32()
            # setup IRP structure
            irp = IRP32()
            irp.irpstack = ctypes.cast(irpstack_addr, ctypes.POINTER(IO_STACK_LOCATION32))

        irpstack.MajorFunction = IRP_MJ_WRITE
        irpstack.Parameters.Write.Length = len(in_buffer)
        self.ql.mem.write(irpstack_addr, bytes(irpstack))

        if device_object.Flags & DO_BUFFERED_IO:
            # BUFFERED_IO
            system_buffer_addr = self.heap.alloc(len(in_buffer))
            alloc_addr.append(system_buffer_addr)
            self.ql.mem.write(system_buffer_addr, bytes(in_buffer))
            irp.AssociatedIrp.SystemBuffer.value = system_buffer_addr
        elif device_object.Flags & DO_DIRECT_IO:
            # DIRECT_IO
            mdl = build_mdl(len(in_buffer))
            if self.archtype == QL_ARCH.X8664:
                mdl_addr = self.heap.alloc(ctypes.sizeof(MDL64))
            else:
                mdl_addr = self.heap.alloc(ctypes.sizeof(MDL32))

            alloc_addr.append(mdl_addr)

            self.ql.mem.write(mdl_addr, bytes(mdl))
            irp.MdlAddress.value = mdl_addr
        else:
            # NEITHER_IO
            input_buffer_size = len(in_buffer)
            input_buffer_addr = self.heap.alloc(input_buffer_size)
            alloc_addr.append(input_buffer_addr)
            self.ql.mem.write(input_buffer_addr, bytes(in_buffer))
            irp.UserBuffer.value = input_buffer_addr

        # everything is done! Write IRP to memory
        self.ql.mem.write(irp_addr, bytes(irp))

        # set function args
        self.set_function_args((self.ql.loader.driver_object.DeviceObject, irp_addr))

        try:
            # now emulate 
            self.ql.run(self.ql.loader.driver_object.MajorFunction[IRP_MJ_WRITE])
        except UcError as err:
            verify_ret(self.ql, err)
            
        # read current IRP state
        if self.archtype == QL_ARCH.X8664:
            irp_buffer = self.ql.mem.read(irp_addr, ctypes.sizeof(IRP64))
            irp = IRP64.from_buffer(irp_buffer)
        else:
            irp_buffer = self.ql.mem.read(irp_addr, ctypes.sizeof(IRP32))
            irp = IRP32.from_buffer(irp_buffer)

        io_status = irp.IoStatus
        # now free all alloc memory
        for addr in alloc_addr:
            # print("freeing heap memory at 0x%x" %addr) # FIXME: the output is not deterministic??
            self.heap.free(addr)
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
    def ioctl(self, params):
        def ioctl_code(DeviceType, Function, Method, Access):
            return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

        alloc_addr = []
        def build_mdl(buffer_size, data=None):
            if self.archtype == QL_ARCH.X8664:
                mdl = MDL64()
            else:
                mdl = MDL32()

            mapped_address = self.heap.alloc(buffer_size)
            alloc_addr.append(mapped_address)
            mdl.MappedSystemVa.value = mapped_address
            mdl.StartVa.value = mapped_address
            mdl.ByteOffset = 0
            mdl.ByteCount = buffer_size
            if data:
                written = data if len(data) <= buffer_size else data[:buffer_size]
                self.ql.mem.write(mapped_address, written)

            return mdl

        # quick simple way to manage all alloc memory
        if self.ql.ostype == QL_OS.WINDOWS:
            # print("DeviceControl callback is at 0x%x" %self.loader.driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL])
            if self.ql.loader.driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL] == 0:
                # raise error?
                return (None, None, None)

            # create new memory region to store input data
            _ioctl_code, output_buffer_size, in_buffer = params
            # extract data transfer method
            devicetype, function, ctl_method, access = _ioctl_code

            input_buffer_size = len(in_buffer)
            input_buffer_addr = self.heap.alloc(input_buffer_size)
            alloc_addr.append(input_buffer_addr)
            self.ql.mem.write(input_buffer_addr, bytes(in_buffer))

            # create new memory region to store out data
            output_buffer_addr = self.heap.alloc(output_buffer_size)
            alloc_addr.append(output_buffer_addr)

            # allocate memory regions for IRP and IO_STACK_LOCATION
            if self.ql.archtype == QL_ARCH.X8664:
                irp_addr = self.heap.alloc(ctypes.sizeof(IRP64))
                alloc_addr.append(irp_addr)
                irpstack_addr = self.heap.alloc(ctypes.sizeof(IO_STACK_LOCATION64))
                alloc_addr.append(irpstack_addr)
                # setup irp stack parameters
                irpstack = IO_STACK_LOCATION64()
                # setup IRP structure
                irp = IRP64()
                irp.irpstack = ctypes.cast(irpstack_addr, ctypes.POINTER(IO_STACK_LOCATION64))
            else:
                irp_addr = self.heap.alloc(ctypes.sizeof(IRP32))
                alloc_addr.append(irp_addr)
                irpstack_addr = self.heap.alloc(ctypes.sizeof(IO_STACK_LOCATION32))
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

            self.ql.nprint("IRP is at 0x%x, IO_STACK_LOCATION is at 0x%x" %(irp_addr, irpstack_addr))

            irpstack.Parameters.DeviceIoControl.IoControlCode = ioctl_code(devicetype, function, ctl_method, access)
            irpstack.Parameters.DeviceIoControl.OutputBufferLength = output_buffer_size
            irpstack.Parameters.DeviceIoControl.InputBufferLength = input_buffer_size
            irpstack.Parameters.DeviceIoControl.Type3InputBuffer.value = input_buffer_addr # used by IOCTL_METHOD_NEITHER
            self.mem.write(irpstack_addr, bytes(irpstack))

            if ctl_method == METHOD_NEITHER:
                irp.UserBuffer.value = output_buffer_addr  # used by IOCTL_METHOD_NEITHER

            # allocate memory for AssociatedIrp.SystemBuffer
            # used by IOCTL_METHOD_IN_DIRECT, IOCTL_METHOD_OUT_DIRECT and IOCTL_METHOD_BUFFERED
            system_buffer_size = max(input_buffer_size, output_buffer_size)
            system_buffer_addr = self.heap.alloc(system_buffer_size)
            alloc_addr.append(system_buffer_addr)

            # init data from input buffer
            self.ql.mem.write(system_buffer_addr, bytes(in_buffer))
            irp.AssociatedIrp.SystemBuffer.value = system_buffer_addr

            if ctl_method in (METHOD_IN_DIRECT, METHOD_OUT_DIRECT):
                # Create MDL structure for output data
                # used by both IOCTL_METHOD_IN_DIRECT and IOCTL_METHOD_OUT_DIRECT
                mdl = build_mdl(output_buffer_size)
                if self.archtype == QL_ARCH.X8664:
                    mdl_addr = self.heap.alloc(ctypes.sizeof(MDL64))
                else:
                    mdl_addr = self.heap.alloc(ctypes.sizeof(MDL32))

                alloc_addr.append(mdl_addr)

                self.ql.mem.write(mdl_addr, bytes(mdl))
                irp.MdlAddress.value = mdl_addr

            # everything is done! Write IRP to memory
            self.ql.mem.write(irp_addr, bytes(irp))

            # set function args
            self.ql.nprint("Executing IOCTL with DeviceObject = 0x%x, IRP = 0x%x" %(self.ql.loader.driver_object.DeviceObject, irp_addr))
            self.set_function_args((self.ql.loader.driver_object.DeviceObject, irp_addr))

            try:
                # now emulate IOCTL's DeviceControl
                self.run(self.loader.driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL])
            except UcError as err:
                verify_ret(self.ql, err)

            # read current IRP state
            if self.archtype == QL_ARCH.X8664:
                irp_buffer = self.ql.mem.read(irp_addr, ctypes.sizeof(IRP64))
                irp = IRP64.from_buffer(irp_buffer)
            else:
                irp_buffer = self.ql.mem.read(irp_addr, ctypes.sizeof(IRP32))
                irp = IRP32.from_buffer(irp_buffer)

            io_status = irp.IoStatus

            # read output data
            output_data = b''
            if io_status.Status.Status >= 0:
                if ctl_method == METHOD_BUFFERED:
                    output_data = self.ql.mem.read(system_buffer_addr, io_status.Information.value)
                if ctl_method in (METHOD_IN_DIRECT, METHOD_OUT_DIRECT):
                    output_data = self.ql.mem.read(mdl.MappedSystemVa.value, io_status.Information.value)
                if ctl_method == METHOD_NEITHER:
                    output_data = self.ql.mem.read(output_buffer_addr, io_status.Information.value)

            # now free all alloc memory
            for addr in alloc_addr:
                # print("freeing heap memory at 0x%x" %addr) # FIXME: the output is not deterministic??
                self.heap.free(addr)
            #print("\n")

            return io_status.Status.Status, io_status.Information.value, output_data
        else: # TODO: IOCTL for non-Windows.
            pass        
