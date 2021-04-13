#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import struct

from qiling.exception import *
from qiling.const import *
from qiling.arch.x86_const import *
from qiling.os.posix.const_mapping import *
from qiling.os.filestruct import *

from .const import *
from .thread import *
from .mach_port import *
from .kernel_func import *
from .utils import *

# TODO: We need to finish these syscall
# there are three kinds of syscall, we often use posix syscall, mach syscall is used by handle mach msg
# Unfortunately we dont have enough doc about mach syscallios 
# We can find all of these syscalls in kernel source code, some pthread func may found in libpthread

################
# ios syscall #
################

def ql_syscall_fgetattrlist(ql, fd, alist, attributeBuffer, bufferSize, options, *args, **kw):
    ql.log.debug("fgetattrlist(fd: 0x%x, alist: 0x%x, attributeBuffer: 0x%x, bufferSize: 0x%x, options: 0x%x)" % (
        fd, alist, attributeBuffer, bufferSize, options
    ))

    attrlist = {}
    attrlist["bitmapcount"] = unpack("<H", ql.mem.read(alist, 2))[0]
    attrlist["reserved"] = unpack("<H", ql.mem.read(alist + 2, 2))[0]
    attrlist["commonattr"] = unpack("<L", ql.mem.read(alist + 4, 4))[0]
    attrlist["volattr"] = unpack("<L", ql.mem.read(alist + 8, 4))[0]
    attrlist["dirattr"] = unpack("<L", ql.mem.read(alist + 12, 4))[0]
    attrlist["fileattr"] = unpack("<L", ql.mem.read(alist + 16, 4))[0]
    attrlist["forkattr"] = unpack("<L", ql.mem.read(alist + 20, 4))[0]

    ql.log.debug("bitmapcount: 0x%x, reserved: 0x%x, commonattr: 0x%x, volattr: 0x%x, dirattr: 0x%x, fileattr: 0x%x, forkattr: 0x%x\n" % (
        attrlist["bitmapcount"], attrlist["reserved"], attrlist["commonattr"], attrlist["volattr"], attrlist["dirattr"], attrlist["fileattr"], attrlist["forkattr"]
    ))

    # path_str = macho_read_string(ql, path, MAX_PATH_SIZE)

    attr = b''
    if attrlist["commonattr"] != 0:
        commonattr = ql.os.macho_fs.get_common_attr(ql.path, attrlist["commonattr"])
        if not commonattr:
            raise QlErrorSyscallError("Error File Not Exist")
        attr += commonattr
    
    attr_len = len(attr) + 4
    attr = struct.pack("<L", attr_len) + attr

    if len(attr) > bufferSize:
        ql.log.debug("Length error")
        return 1
    else:

        ql.mem.write(attributeBuffer, attr)
        #set_eflags_cf(ql, 0x0)
        return KERN_SUCCESS


def ql_syscall_poll(ql, target, address, size, *args, **kw):
    return KERN_SUCCESS


################
# mach syscall #
################

# 0xa
def ql_syscall_kernelrpc_mach_vm_allocate_trap(ql, port, addr, size, flags, *args, **kw):
    ql.log.debug("[mach] mach vm allocate trap(port: 0x%x, addr: 0x%x, size: 0x%x, flags: 0x%x" % (port, addr, size, flags))
    mmap_address = ql.os.macho_task.min_offset
    mmap_end = page_align_end(mmap_address + size, PAGE_SIZE)
    ql.mem.map(mmap_address, mmap_end - mmap_address)
    ql.mem.write(mmap_address, b'\x00'*(mmap_end - mmap_address))
    ql.os.macho_task.min_offset = mmap_end
    ql.log.debug("vm alloc form 0x%x to 0x%0x" % (mmap_address, mmap_end))
    ql.mem.write(addr, struct.pack("<Q", mmap_address))
    return 0

# 0xc
def ql_syscall_kernelrpc_mach_vm_deallocate_trap(ql, target, address, size, *args, **kw):
    ql.log.debug("[mach] mach vm deallocate trap")
    return KERN_SUCCESS

# 0xf
def ql_syscall_kernelrpc_mach_vm_map_trap(ql, target, address, size, mask, flags, cur_protection):
    ql.log.debug("[mach] mach vm map trap(target: 0x%x, address: 0x%x, size: 0x%x, mask: 0x%x, flag: 0x%x, cur_protect: 0x%x)" % (
        target, address, size, mask, flags, cur_protection
    ))

    if ql.os.macho_vmmap_end & mask > 0:
        ql.os.macho_vmmap_end = ql.os.macho_vmmap_end - (ql.os.macho_vmmap_end & mask)
        ql.os.macho_vmmap_end += mask + 1

    
    vmmap_address = page_align_end(ql.os.macho_vmmap_end, PAGE_SIZE)
    vmmap_end = page_align_end(vmmap_address + size, PAGE_SIZE)

    ql.os.macho_vmmap_end = vmmap_end
    ql.mem.map(vmmap_address, vmmap_end - vmmap_address)
    ql.mem.write(address, struct.pack("<Q", vmmap_address))
    return KERN_SUCCESS

# 0x12
def ql_syscall_kernelrpc_mach_port_deallocate_trap(ql, *args, **kw):
    ql.log.debug("[mach] mach port deallocate trap")

# 0x13
def ql_syscall_kernelrpc_mach_port_mod_refs_trap(ql, target, name, right, delta, *args, **kw):
    ql.log.debug("[mach] mach port mod refs trap(target: 0x%x, name: 0x%x, right: 0x%x, delta: 0x%x)" % (
        target, name, right, delta
    ))
    pass

# 0x18
def ql_syscall_kernelrpc_mach_port_construct_trap(ql, target, options, context, name, *args, **kw):
    ql.log.debug("[mach] mach port construct trap(target: 0x%x, options: 0x%x, context: 0x%x, name: 0x%x)" % (
        target, options, context, name
    ))
    pass

# 0x1a
def ql_syscall_mach_reply_port(ql, *args, **kw):
    ql.log.debug("[mach] mach reply port , ret: %s" % (ql.os.macho_mach_port.name))
    return ql.os.macho_mach_port.name

# 0x1b
def ql_syscall_thread_self_trap(ql, *args, **kw):
    port_manager = ql.os.macho_port_manager
    thread_port = port_manager.get_thread_port(ql.os.macho_thread)
    ql.log.debug("[mach] thread_self_trap: ret: %s" % (thread_port))
    return thread_port

# 0x1c
def ql_syscall_task_self_trap(ql, *args, **kw):
    ql.log.debug("[mach] task self trap, ret: %d" % (ql.os.macho_task.id))
    return ql.os.macho_task.id

# 0x1d
def ql_syscall_host_self_trap(ql, *args, **kw):
    port_manager = ql.os.macho_port_manager
    ql.log.debug("[mach] host_self_trap, ret: %s" % (ql.os.macho_port_manager.host_port.name))
    return port_manager.host_port.name

# 0x1f
def ql_syscall_mach_msg_trap(ql, args, opt, ssize, rsize, rname, timeout):
    ql.log.debug("[mach] mach_msg_trap(args: 0x%x opt: 0x%x, ssize: 0x%x, rsize: 0x%x, rname: 0x%x, timeout: %d)" % (
        args, opt, ssize, rsize, rname, timeout))
    mach_msg = MachMsg(ql)
    mach_msg.read_msg_from_mem(args, ssize)
    ql.log.debug("Recv-> Header: %s, Content: %s" % (mach_msg.header, mach_msg.content))
    ql.os.macho_port_manager.deal_with_msg(mach_msg, args)
    return 0


#################
# POSIX syscall #
#################

# 0x21
def ql_syscall_access_macos(ql, path, flags, *args, **kw):
    path_str = ql.os.utils.read_cstring(path)
    ql.log.debug("access(path: %s, flags: 0x%x)" % (path_str, flags))
    if not ql.os.macho_fs.isexists(path_str):
        return ENOENT
    else:
        return KERN_SUCCESS

# 0x30 
def ql_syscall_sigprocmask(ql, how, mask, omask, *args, **kw):
    ql.log.debug("sigprocmask(how: 0x%x, mask: 0x%x, omask: 0x%x)" % (how, mask, omask))

# 0x5c
def ql_syscall_fcntl64_macos(ql, fcntl_fd, fcntl_cmd, fcntl_arg, *args, **kw):
    regreturn = 0
    if fcntl_cmd == F_GETFL:
        regreturn = 2
    elif fcntl_cmd == F_SETFL:
        regreturn = 0
    elif fcntl_cmd == F_GETFD:
        regreturn = 2
    elif fcntl_cmd == F_SETFD:
        regreturn = 0
    elif fcntl_cmd == F_ADDFILESIGS_RETURN:
        ql.mem.write(fcntl_arg, ql.pack32(0xefffffff))
        regreturn = 0
    else:
        regreturn = 0

    ql.log.debug("fcntl64(fd: %d, cmd: %d, arg: 0x%x) = %d" % (fcntl_fd, fcntl_cmd, fcntl_arg, regreturn))
    return regreturn

# 0x99
def ql_syscall_pread(ql, fd, buf, nbyte, offset, *args, **kw):
    ql.log.debug("pread(fd: 0x%x, buf: 0x%x, nbyte: 0x%x, offset: 0x%x)" % (
        fd, buf, nbyte, offset
    ))
    if fd >= 0 and fd <= MAX_FD_SIZE:
        ql.os.fd[fd].lseek(offset)
        data = ql.os.fd[fd].read(nbyte)
        ql.mem.write(buf, data)
    set_eflags_cf(ql, 0x0)
    return nbyte

# 0xa9
def ql_syscall_csops(ql, pid, ops, useraddr, usersize, *args, **kw):
    flag = struct.pack("<L", (CS_ENFORCEMENT | CS_GET_TASK_ALLOW))
    ql.mem.write(useraddr, flag)
    ql.log.debug("csops(pid: %d, ops: 0x%x, useraddr: 0x%x, usersize: 0x%x) flag: 0x%x" % (
        pid, ops, useraddr, usersize, ((CS_ENFORCEMENT | CS_GET_TASK_ALLOW))
    ))
    return KERN_SUCCESS

# 0xdc
def ql_syscall_getattrlist(ql, path, alist, attributeBuffer, bufferSize, options, *args, **kw):
    ql.log.debug("getattrlist(path: 0x%x, alist: 0x%x, attributeBuffer: 0x%x, bufferSize: 0x%x, options: 0x%x)" % (
        path, alist, attributeBuffer, bufferSize, options
    ))
    attrlist = {}
    attrlist["bitmapcount"] = unpack("<H", ql.mem.read(alist, 2))[0]
    attrlist["reserved"] = unpack("<H", ql.mem.read(alist + 2, 2))[0]
    attrlist["commonattr"] = unpack("<L", ql.mem.read(alist + 4, 4))[0]
    attrlist["volattr"] = unpack("<L", ql.mem.read(alist + 8, 4))[0]
    attrlist["dirattr"] = unpack("<L", ql.mem.read(alist + 12, 4))[0]
    attrlist["fileattr"] = unpack("<L", ql.mem.read(alist + 16, 4))[0]
    attrlist["forkattr"] = unpack("<L", ql.mem.read(alist + 20, 4))[0]
    path_str = ql.os.utils.read_cstring(path)

    ql.log.debug("bitmapcount: 0x%x, reserved: 0x%x, commonattr: 0x%x, volattr: 0x%x, dirattr: 0x%x, fileattr: 0x%x, forkattr: 0x%x\n" % (
        attrlist["bitmapcount"], attrlist["reserved"], attrlist["commonattr"], attrlist["volattr"], attrlist["dirattr"], attrlist["fileattr"], attrlist["forkattr"]
    ))
    ql.log.debug("path str: %s\n" % (path_str))

    attr = b''
    if attrlist["commonattr"] != 0:
        commonattr = ql.os.macho_fs.get_common_attr(path_str, attrlist["commonattr"])
        if not commonattr:
            ql.log.debug("Error File Not Exist: %s" % (path_str))
            raise QlErrorSyscallError("Error File Not Exist %s" % path_str)
        attr += commonattr
    
    attr_len = len(attr) + 4
    attr = struct.pack("<L", attr_len) + attr

    if len(attr) > bufferSize:
        ql.log.debug("Length error")
        return 1
    else:
        ql.mem.write(attributeBuffer, attr)
        set_eflags_cf(ql, 0x0)
        return KERN_SUCCESS

# 0xc2
# struct rlimit {
#     rlim_t	rlim_cur;		/* current (soft) limit */       uint64
#     rlim_t	rlim_max;		/* maximum value for rlim_cur */ uint64
# };
def ql_syscall_getrlimit(ql, which, rlp, *args, **kw):
    ql.log.debug("getrlimit(which:0x%x, rlp:0x%x)" % (which, rlp))
    _RLIMIT_POSIX_FLAG = 0x1000
    RLIM_NLIMITS = 9
    which = which & _RLIMIT_POSIX_FLAG
    if which >= RLIM_NLIMITS:
        return EINVAL
    else:
        ql.mem.write(rlp, b'\x00\x13\x00\x00\x00\x00\x00\x00')  # rlim_cur
        ql.mem.write(rlp, b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F')  # rlim_max
        pass
    pass

# 0xca
def ql_syscall_sysctl(ql, name, namelen, old, oldlenp, new_arg, newlen):
    ql.log.debug("sysctl(name: 0x%x, namelen: 0x%x, old: 0x%x, oldlenp: 0x%x, new: 0x%x, newlen: 0x%x)" % (
        name, namelen, old, oldlenp, new_arg, newlen
    ))
    return KERN_SUCCESS

# 0x112
def ql_syscall_sysctlbyname(ql, name, namelen, old, oldlenp, new_arg, newlen):
    ql.log.debug("sysctlbyname(name: 0x%x, namelen: 0x%x, old: 0x%x, oldlenp: 0x%x, new: 0x%x, newlen: 0x%x)" % (
        name, namelen, old, oldlenp, new_arg, newlen
    ))
    return KERN_SUCCESS

# 0x126
# check shared region if avalible , return not ready every time
def ql_syscall_shared_region_check_np(ql, p, uap, retvalp, *args, **kw):
    ql.log.debug("shared_region_check_np(p: 0x%x, uap: 0x%x, retvalp: 0x%x) = 0x%x" % (p, uap, retvalp, EINVAL))
    return EINVAL

# 0x150
def ql_syscall_proc_info(ql, callnum, pid, flavor, arg, buff, buffer_size):
    retval = struct.unpack("<Q", ql.mem.read(ql.reg.rsp, 8))[0]
    ql.log.debug("proc_info(callnum: 0x%x, pid: %d, flavor:0x%x, arg: 0x%x, buffer: 0x%x, buffersize: 0x%x, retval: 0x%x)" % (
        callnum, pid, flavor, arg, buff, buffer_size, retval
    ))
    if callnum == PROC_INFO_CALL_PIDINFO:
        if flavor == PROC_PIDREGIONPATHINFO:
            info = ProcRegionWithPathInfo(ql)
            info.set_path(b"/usr/lib/dyld")
            info.write_info(buff)
        pass
    pass


# 0x16e
def ql_syscall_bsdthread_register(ql, threadstart, wqthread, flags, stack_addr_hint, targetconc_ptr, dispatchqueue_offset):
    set_eflags_cf(ql, 0x0)
    return 0x00000000400000df

# 0x174
def ql_syscall_thread_selfid(ql, *args, **kw):
    thread_id = ql.os.macho_thread.id
    return thread_id


# 0x18d
def ql_syscall_write_nocancel(ql, write_fd, write_buf, write_count, *args, **kw):
    regreturn = 0
    buf = None

    try:
        buf = ql.mem.read(write_buf, write_count)
        if buf:
            ql.log.debug("write() CONTENT:")
            ql.log.debug("%s" % buf)

        if hasattr(ql.os.fd[write_fd], "write"):
            ql.os.fd[write_fd].write(buf)
        else:
            ql.log.debug("write(%d,%x,%i) failed due to write_fd" % (write_fd, write_buf, write_count, regreturn))
        regreturn = write_count

    except:
        regreturn = -1

        if ql.verbose >= QL_VERBOSE.DEBUG:
            raise
    #if buf:
    #    ql.log.info(buf.decode(errors='ignore'))
    return 0


# 0x18e
def ql_syscall_open_nocancel(ql, filename, flags, mode, *args, **kw):
    path = ql.mem.string(filename)
    relative_path = ql.os.path.transform_to_relative_path(path)

    flags = flags & 0xffffffff
    mode = mode & 0xffffffff

    for i in range(256):
        if ql.os.fd[i] == 0:
            idx = i
            break

    if idx == -1:
        regreturn = -1
    else:
        try:
            if ql.archtype== QL_ARCH.ARM:
                mode = 0

            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(path, flags, mode)
            regreturn = idx
        except QlSyscallError:
            regreturn = -1

    if regreturn >= 0 and regreturn != 2:
        ql.log.debug("File Found: %s" % relative_path)
    else:
        ql.log.debug("File Not Found %s" % relative_path)
    return regreturn

# 0x1b6
def ql_syscall_shared_region_map_and_slide_np(ql, fd, count, mappings_addr, slide, slide_start, slide_size):
    ql.log.debug("shared_region_map_and_slide_np(fd: %d, count: 0x%x, mappings: 0x%x, slide: 0x%x, slide_start: 0x%x, slide_size: 0x%x)" % (
                fd, count ,mappings_addr, slide, slide_start, slide_size
            ))
    mapping_list = []
    for i in range(count):
        mapping = SharedFileMappingNp(ql)
        mapping.read_mapping(mappings_addr)
        ql.os.fd[fd].lseek(mapping.sfm_file_offset)
        content = ql.os.fd[fd].read(mapping.sfm_size)
        ql.mem.write(mapping.sfm_address, content)
        mappings_addr += mapping.size
        mapping_list.append(mapping)
    return slide_size

# 0x1e3
def ql_syscall_csrctl(ql, op, useraddr, usersize, *args, **kw):
    ql.log.debug("csrctl(op: 0x%x, useraddr :0x%x, usersize: 0x%x)" % (op, useraddr, usersize))
    return 1

# 0x1f4
def ql_syscall_getentropy(ql, buffer, size, *args, **kw):
    ql.log.debug("getentropy(buffer: 0x%x, size: 0x%x)" % (buffer, size))
    return KERN_SUCCESS

# 0x208
def ql_syscall_terminate_with_payload(ql, pid, reason_namespace, reason_code, payload, payload_size, reason_string):
    ql.log.debug("terminate_with_payload(pid: %d, reason_namespace: 0x%x, reason_code: 0x%x, payload: 0x%x \
            payload_size: 0x%x, reason_string: 0x%x)" % (pid, reason_namespace, reason_code,
            payload, payload_size, reason_string))
    ql.emu_stop()
    return KERN_SUCCESS

# 0x209
def ql_syscall_abort_with_payload(ql, reason_namespace, reason_code, payload, payload_size, reason_string, reason_flags):
    ql.log.debug("abort_with_payload(reason_namespace: 0x%x, reason_code: 0x%x, payload: 0x%x, payload_size: 0x%x, reason_string: 0x%x,\
            reason_flags: 0x%x)" % (reason_namespace, reason_code, payload, payload_size, reason_string, reason_flags))
    return KERN_SUCCESS



################
# mdep syscall #
################

# 0x3d
# thread_set_tsd_base
def ql_syscall_thread_fast_set_cthread_self64(ql, u_info_addr, *args, **kw):
    ql.log.debug("[mdep] thread fast set cthread self64(tsd_base:0x%x)" % (u_info_addr))
    ql.reg.msr(GSMSR, u_info_addr)
    return KERN_SUCCESS
