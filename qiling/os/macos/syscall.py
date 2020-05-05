#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

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


def ql_arm64_fgetattrlist(ql, fd, attrlist, attrbuff, attrsizebuff, options, *args, **kw):
    ql.nprint("fgetattrlist(fd: %d, attrlist: 0x%x, attrbuff: 0x%x, attrsizebuff: 0x%x, options: 0x%x)" % (
            fd, attrlist, attrbuff, attrsizebuff, options))

    ql.dprint(D_INFO, "[+] addr: 0x%x, path: %s" % (attrlist ,attrbuff))
    KERN_SUCCESS = 1
    ql.os.definesyscall_return(KERN_SUCCESS)


def ql_arm64_poll(ql, target, address, size, *args, **kw):
    ql.os.definesyscall_return(KERN_SUCCESS)
    # FIXME:
    ql.nprint("FIXME: syscall[poll] >> exit for now")
    exit()


################
# mach syscall #
################

# 0xa
def ql_x86_syscall_kernelrpc_mach_vm_allocate_trap(ql, port, addr, size, flags, *args, **kw):
    ql.dprint(D_INFO, "[+] [mach] mach vm allocate trap(port: 0x%x, addr: 0x%x, size: 0x%x, flags: 0x%x" % (port, addr, size, flags))
    mmap_address = ql.os.macho_task.min_offset
    mmap_end = page_align_end(mmap_address + size, PAGE_SIZE)
    ql.mem.map(mmap_address, mmap_end - mmap_address)
    ql.mem.write(mmap_address, b'\x00'*(mmap_end - mmap_address))
    ql.os.macho_task.min_offset = mmap_end
    ql.dprint(D_INFO, "[+] vm alloc form 0x%x to 0x%0x" % (mmap_address, mmap_end))
    ql.mem.write(addr, struct.pack("<Q", mmap_address))
    ql.os.definesyscall_return(0)

# 0xc
def ql_x86_syscall_kernelrpc_mach_vm_deallocate_trap(ql, target, address, size, *args, **kw):
    ql.os.definesyscall_return(KERN_SUCCESS)
    ql.dprint(D_INFO, "[+] [mach] mach vm deallocate trap")

# 0xf
def ql_x86_syscall_kernelrpc_mach_vm_map_trap(ql, target, address, size, mask, flags, cur_protection):
    ql.dprint(D_INFO, "[+] [mach] mach vm map trap(target: 0x%x, address: 0x%x, size: 0x%x, mask: 0x%x, flag: 0x%x, cur_protect: 0x%x)" % (
        target, address, size, mask, flags, cur_protection
    ))

    if ql.macho_vmmap_end & mask > 0:
        ql.macho_vmmap_end = ql.macho_vmmap_end - (ql.macho_vmmap_end & mask)
        ql.macho_vmmap_end += mask + 1

    
    vmmap_address = page_align_end(ql.macho_vmmap_end, PAGE_SIZE)
    vmmap_end = page_align_end(vmmap_address + size, PAGE_SIZE)

    ql.macho_vmmap_end = vmmap_end
    ql.mem.map(vmmap_address, vmmap_end - vmmap_address)
    ql.mem.write(address, struct.pack("<Q", vmmap_address))
    ql.os.definesyscall_return(KERN_SUCCESS)

# 0x12
def ql_x86_syscall_kernelrpc_mach_port_deallocate_trap(ql, *args, **kw):
    ql.dprint(D_INFO, "[+] [mach] mach port deallocate trap")

# 0x13
def ql_x86_syscall_kernelrpc_mach_port_mod_refs_trap(ql, target, name, right, delta, *args, **kw):
    ql.dprint(D_INFO, "[+] [mach] mach port mod refs trap(target: 0x%x, name: 0x%x, right: 0x%x, delta: 0x%x)" % (
        target, name, right, delta
    ))
    pass

# 0x18
def ql_x86_syscall_kernelrpc_mach_port_construct_trap(ql, target, options, context, name, *args, **kw):
    ql.dprint(D_INFO, "[+] [mach] mach port construct trap(target: 0x%x, options: 0x%x, context: 0x%x, name: 0x%x)" % (
        target, options, context, name
    ))
    pass

# 0x1a
def ql_x86_syscall_mach_reply_port(ql, *args, **kw):
    ql.os.definesyscall_return(ql.os.macho_mach_port.name)
    ql.dprint(D_INFO, "[+] [mach] mach reply port , ret: %s" % (ql.os.macho_mach_port.name))

# 0x1b
def ql_x86_syscall_thread_self_trap(ql, *args, **kw):
    port_manager = ql.os.macho_port_manager
    thread_port = port_manager.get_thread_port(ql.os.macho_thread)
    ql.dprint(D_INFO, "[+] [mach] thread_self_trap: ret: %s" % (thread_port))
    ql.os.definesyscall_return(thread_port)

# 0x1c
def ql_x86_syscall_task_self_trap(ql, *args, **kw):
    ql.os.definesyscall_return(ql.os.macho_task.id)
    ql.dprint(D_INFO, "[+] [mach] task self trap, ret: %d" % (ql.os.macho_task.id))

# 0x1d
def ql_x86_syscall_host_self_trap(ql, *args, **kw):
    port_manager = ql.os.macho_port_manager
    ql.os.definesyscall_return(port_manager.host_port.name)
    ql.dprint(D_INFO, "[+] [mach] host_self_trap, ret: %s" % (666))

# 0x1f
def ql_x86_syscall_mach_msg_trap(ql, args, opt, ssize, rsize, rname, timeout):
    ql.dprint(D_INFO, "[+] [mach] mach_msg_trap(args: 0x%x opt: 0x%x, ssize: 0x%x, rsize: 0x%x, rname: 0x%x, timeout: %d)" % (
        args, opt, ssize, rsize, rname, timeout))
    mach_msg = MachMsg(ql)
    mach_msg.read_msg_from_mem(args, ssize)
    ql.dprint(D_INFO, "[+] Recv-> Header: %s, Content: %s" % (mach_msg.header, mach_msg.content))
    ql.os.macho_port_manager.deal_with_msg(mach_msg, args)
    ql.os.definesyscall_return(0)


#################
# POSIX syscall #
#################

# 0x21
def ql_syscall_access_macos(ql, path, flags, *args, **kw):
    path_str = macho_read_string(ql, path, MAX_PATH_SIZE)
    ql.nprint("access(%s, 0x%x)" % (path_str, flags))
    ql.dprint(D_INFO, "[+] access(path: %s, flags: 0x%x)" % (path_str, flags))
    if not ql.os.macho_fs.isexists(path_str):
        ql.os.definesyscall_return(ENOENT)
    else:
        ql.os.definesyscall_return(KERN_SUCCESS)

# 0x30 
def ql_syscall_sigprocmask(ql, how, mask, omask, *args, **kw):
    ql.nprint("sigprocmask(how: 0x%x, mask: 0x%x, omask: 0x%x)" % (how, mask, omask))

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

    ql.nprint("fcntl64(fd: %d, cmd: %d, arg: 0x%x) = %d" % (fcntl_fd, fcntl_cmd, fcntl_arg, regreturn))
    ql.os.definesyscall_return(regreturn)

# 0x99
def ql_syscall_pread(ql, fd, buf, nbyte, offset, *args, **kw):
    ql.nprint("pread(fd: 0x%x, buf: 0x%x, nbyte: 0x%x, offset: 0x%x)" % (
        fd, buf, nbyte, offset
    ))
    if fd >= 0 and fd <= MAX_FD_SIZE:
        ql.os.file_des[fd].lseek(offset)
        data = ql.os.file_des[fd].read(nbyte)
        ql.mem.write(buf, data)
    set_eflags_cf(ql, 0x0)
    ql.os.definesyscall_return(nbyte)

# 0xa9
def ql_syscall_csops(ql, pid, ops, useraddr, usersize, *args, **kw):
    flag = struct.pack("<L", (CS_ENFORCEMENT | CS_GET_TASK_ALLOW))
    ql.mem.write(useraddr, flag)
    ql.nprint("csops(pid: %d, ops: 0x%x, useraddr: 0x%x, usersize: 0x%x) flag: 0x%x" % (
        pid, ops, useraddr, usersize, ((CS_ENFORCEMENT | CS_GET_TASK_ALLOW))
    ))
    ql.os.definesyscall_return(KERN_SUCCESS)

# 0xdc
def ql_syscall_getattrlist(ql, path, alist, attributeBuffer, bufferSize, options, *args, **kw):
    ql.nprint("getattrlist(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)" % (
        path, alist, attributeBuffer, bufferSize, options
    ))

    ql.dprint(D_INFO, "getattrlist(path: 0x%x, alist: 0x%x, attributeBuffer: 0x%x, bufferSize: 0x%x, options: 0x%x)" % (
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
    path_str = macho_read_string(ql, path, MAX_PATH_SIZE)

    ql.dprint(D_INFO, "[+] bitmapcount: 0x%x, reserved: 0x%x, commonattr: 0x%x, volattr: 0x%x, dirattr: 0x%x, fileattr: 0x%x, forkattr: 0x%x\n" % (
        attrlist["bitmapcount"], attrlist["reserved"], attrlist["commonattr"], attrlist["volattr"], attrlist["dirattr"], attrlist["fileattr"], attrlist["forkattr"]
    ))
    ql.dprint(D_INFO, "[+] path str: %s\n" % (path_str))

    attr = b''
    if attrlist["commonattr"] != 0:
        commonattr = ql.os.macho_fs.get_common_attr(path_str, attrlist["commonattr"])
        if not commonattr:
            ql.dprint(D_INFO, "Error File Not Exist: %s" % (path_str))
            raise QlErrorSyscallError("Error File Not Exist")
        attr += commonattr
    
    attr_len = len(attr) + 4
    attr = struct.pack("<L", attr_len) + attr

    if len(attr) > bufferSize:
        ql.dprint(D_INFO, "Length error")
        ql.os.definesyscall_return(1)
    else:
        ql.mem.write(attributeBuffer, attr)
        set_eflags_cf(ql, 0x0)
        ql.os.definesyscall_return(KERN_SUCCESS)

# 0xc2
# struct rlimit {
#     rlim_t	rlim_cur;		/* current (soft) limit */       uint64
#     rlim_t	rlim_max;		/* maximum value for rlim_cur */ uint64
# };
def ql_syscall_getrlimit(ql, which, rlp, *args, **kw):
    ql.nprint("getrlimit(0x%x, 0x%x)" % (which, rlp))
    ql.dprint(D_INFO, "[+] getrlimit(which:0x%x, rlp:0x%x)" % (which, rlp))
    _RLIMIT_POSIX_FLAG = 0x1000
    RLIM_NLIMITS = 9
    which = which & _RLIMIT_POSIX_FLAG
    if which >= RLIM_NLIMITS:
        ql.os.definesyscall_return(EINVAL)
    else :
        ql.mem.write(rlp, b'\x00\x13\x00\x00\x00\x00\x00\x00')  # rlim_cur
        ql.mem.write(rlp, b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F')  # rlim_max
        pass
    pass

# 0xc5
# this is ugly patch, we might need to get value from elf parse,
# is32bit or is64bit value not by arch
def ql_syscall_mmap2_macos(ql, mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset):
    MAP_ANONYMOUS=32

    if (ql.archtype== QL_ARCH.ARM64) or (ql.archtype== QL_ARCH.X8664):
        mmap2_fd = ql.unpack64(ql.pack64(mmap2_fd))

    elif (ql.archtype== QL_ARCH.MIPS):
        mmap2_fd = ql.unpack32s(ql.mem.read(mmap2_fd, 4))
        mmap2_pgoffset = ql.unpack32(ql.mem.read(mmap2_pgoffset, 4)) * 4096
        MAP_ANONYMOUS=2048
    else:
        mmap2_fd = ql.unpack32s(ql.pack32(mmap2_fd))
        mmap2_pgoffset = mmap2_pgoffset * 4096

    mmap_base = mmap2_addr
    need_mmap = True

    if mmap2_addr != 0 and mmap2_addr < ql.loader.mmap_address:
        need_mmap = False
    if mmap2_addr == 0:
        mmap_base = ql.loader.mmap_address
        ql.loader.mmap_address = mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000

    ql.dprint(D_INFO, "[+] log mmap - mmap2(0x%x, %d, 0x%x, 0x%x, %d, %d)" % (mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset))
    ql.dprint(D_INFO, "[+] log mmap - return addr : " + hex(mmap_base))
    ql.dprint(D_INFO, "[+] log mmap - addr range  : " + hex(mmap_base) + ' - ' + hex(mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))

    if need_mmap:
        ql.dprint(D_INFO, "[+] log mmap - mapping needed")
        try:
            ql.mem.map(mmap_base, ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000)
        except:
            pass

    ql.mem.write(mmap_base, b'\x00' * (((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))
    
    if ((mmap2_flags & MAP_ANONYMOUS) == 0) and mmap2_fd < 256 and ql.os.file_des[mmap2_fd] != 0:
        ql.os.file_des[mmap2_fd].lseek(mmap2_pgoffset)
        data = ql.os.file_des[mmap2_fd].read(mmap2_length)

        ql.dprint(D_INFO, "[+] log mem wirte : " + hex(len(data)))
        ql.dprint(D_INFO, "[+] log mem mmap  : " + str(ql.os.file_des[mmap2_fd].name))
        ql.mem.write(mmap_base, data)
        
        mem_info = ql.os.file_des[mmap2_fd].name

    if ql.output == QL_OUTPUT.DEFAULT:
        ql.nprint("mmap2(0x%x, %d, 0x%x, 0x%x, %d, %d) = 0x%x" % (mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset, mmap_base))
    
    regreturn = mmap_base
    ql.dprint(D_INFO, "[+] mmap_base is 0x%x" % regreturn)

    ql.os.definesyscall_return(regreturn)

# 0xca
def ql_syscall_sysctl(ql, name, namelen, old, oldlenp, new_arg, newlen):
    ql.nprint("sysctl(name: 0x%x, namelen: 0x%x, old: 0x%x, oldlenp: 0x%x, new: 0x%x, newlen: 0x%x)" % (
        name, namelen, old, oldlenp, new_arg, newlen
    ))
    ql.os.definesyscall_return(KERN_SUCCESS)

# 0x112
def ql_syscall_sysctlbyname(ql, name, namelen, old, oldlenp, new_arg, newlen):
    ql.nprint("sysctlbyname(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)" % (
        name, namelen, old, oldlenp, new_arg, newlen
    ))
    ql.dprint(D_INFO, "[+] sysctlbyname(name: 0x%x, namelen: 0x%x, old: 0x%x, oldlenp: 0x%x, new: 0x%x, newlen: 0x%x)" % (
        name, namelen, old, oldlenp, new_arg, newlen
    ))
    ql.os.definesyscall_return(KERN_SUCCESS)

# 0x126
# check shared region if avalible , return not ready every time
def ql_syscall_shared_region_check_np(ql, p, uap, retvalp, *args, **kw):
    ql.nprint("shared_region_check_np(0x%x, 0x%x, 0x%x) =  0x%x" % (p, uap, retvalp, EINVAL))
    ql.dprint(D_INFO, "[+] shared_region_check_np(p: 0x%x, uap: 0x%x, retvalp: 0x%x) = 0x%x" % (p, uap, retvalp, EINVAL))
    ql.os.definesyscall_return(EINVAL)

# 0x150
def ql_syscall_proc_info(ql, callnum, pid, flavor, arg, buff, buffer_size):
    retval = struct.unpack("<Q", ql.mem.read(ql.reg.rsp, 8))[0]
    ql.nprint("proc_info(0x%x, %d, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)" % (
        callnum, pid, flavor, arg, buff, buffer_size, retval
    ))
    ql.nprint("[+] proc_info(callnum: 0x%x, pid: %d, flavor:0x%x, arg: 0x%x, buffer: 0x%x, buffersize: 0x%x, retval: 0x%x)" % (
        callnum, pid, flavor, arg, buff, buffer_size, retval
    ))
    if callnum == PROC_INFO_CALL_PIDINFO:
        if flavor == PROC_PIDREGIONPATHINFO:
            info = ProcRegionWithPathInfo(ql)
            info.set_path(b"/usr/lib/dyld")
            info.write_info(buff)
        pass
    pass

# 0x152
def ql_syscall_stat64_macos(ql, stat64_pathname, stat64_buf_ptr, *args, **kw):
    stat64_file = (ql.mem.string(stat64_pathname))

    real_path = ql.os.macho_fs.vm_to_real_path(stat64_file)
    ql.dprint(D_INFO, "real_path: %s" % (real_path))
    if os.path.exists(real_path) == False:
        regreturn = -1
    else:
        stat64_info = os.stat(real_path)
        stat64_buf = ql.pack32(stat64_info.st_dev)              # st_dev            32byte
        stat64_buf += ql.pack32(stat64_info.st_mode)            # st_mode           16(32)byte
        stat64_buf += ql.pack32(stat64_info.st_nlink)           # st_nlink          16(32)byte
        stat64_buf += ql.pack64(stat64_info.st_ino)             # st_ino            64 byte
        stat64_buf += ql.pack32(0x0)                            # st_uid            32 byte
        stat64_buf += ql.pack32(0x0)                            # st_gid            32 byte
        stat64_buf += ql.pack32(0x0)                            # st_rdev           32 byte
        stat64_buf += ql.pack64(int(stat64_info.st_atime))      # st_atime          64 byte
        stat64_buf += ql.pack64(0x0)                            # st_atimensec      64 byte
        stat64_buf += ql.pack64(int(stat64_info.st_mtime))      # st_mtime          64 byte
        stat64_buf += ql.pack64(0x0)                            # st_mtimensec      64 byte
        stat64_buf += ql.pack64(int(stat64_info.st_ctime))      # st_ctime          64 byte
        stat64_buf += ql.pack64(0x0)                            # st_ctimensec      64 byte
        if ql.platform == QL_OS.MACOS:
            stat64_buf += ql.pack64(int(stat64_info.st_birthtime))  # st_birthtime      64 byte
        else:
            stat64_buf += ql.pack64(int(stat64_info.st_ctime))  # st_birthtime      64 byte
        stat64_buf += ql.pack64(0x0)                            # st_birthtimensec  64 byte
        stat64_buf += ql.pack64(stat64_info.st_size)            # st_size           64 byte
        stat64_buf += ql.pack64(stat64_info.st_blocks)          # st_blocks         64 byte
        stat64_buf += ql.pack32(stat64_info.st_blksize)         # st_blksize        32 byte
        if ql.platform == QL_OS.MACOS:
            stat64_buf += ql.pack32(stat64_info.st_flags)       # st_flags          32 byte
        else:    
            stat64_buf += ql.pack32(0x0)          
        if ql.platform == QL_OS.MACOS:
            stat64_buf += ql.pack32(stat64_info.st_gen)         # st_gen            32 byte
        else:    
            stat64_buf += ql.pack32(0x0)
        stat64_buf += ql.pack32(0x0)                            # st_lspare         32 byte
        stat64_buf += ql.pack64(0x0)                            # st_qspare         64 byte

        ql.mem.write(stat64_buf_ptr, stat64_buf)
        regreturn = 0
    ql.nprint("stat64(%s, 0x%x) = %d" % (stat64_file, stat64_buf_ptr, regreturn))
    if regreturn == 0:
        set_eflags_cf(ql, 0x0)
        ql.dprint(D_INFO, "[+] stat64 write completed")
    else:
        ql.dprint(D_INFO, "[!] stat64 read/write fail")
    ql.os.definesyscall_return(regreturn)

# 0x153
def ql_syscall_fstat64_macos(ql, fstat64_fd, fstat64_add, *args, **kw):
    fstat64_buf = b''
    if fstat64_fd < 256 and ql.os.file_des[fstat64_fd] != 0:
        user_fileno = fstat64_fd
        fstat64_info = ql.os.file_des[user_fileno].fstat()
        
        if ql.archtype== QL_ARCH.ARM64:
            fstat64_buf = ql.pack64(fstat64_info.st_dev)
            fstat64_buf += ql.pack64(fstat64_info.st_ino)
            fstat64_buf += ql.pack32(fstat64_info.st_mode)
            fstat64_buf += ql.pack32(fstat64_info.st_nlink)
            fstat64_buf += ql.pack32(1000)
            fstat64_buf += ql.pack32(1000)
            fstat64_buf += ql.pack64(fstat64_info.st_rdev)
            fstat64_buf += ql.pack64(0)
            fstat64_buf += ql.pack64(fstat64_info.st_size)
            fstat64_buf += ql.pack32(fstat64_info.st_blksize)
            fstat64_buf += ql.pack32(0)
            fstat64_buf += ql.pack64(fstat64_info.st_blocks)
            fstat64_buf += ql.pack64(int(fstat64_info.st_atime))
            fstat64_buf += ql.pack64(0)
            fstat64_buf += ql.pack64(int(fstat64_info.st_mtime))
            fstat64_buf += ql.pack64(0)
            fstat64_buf += ql.pack64(int(fstat64_info.st_ctime))
            fstat64_buf += ql.pack64(0)
        elif ql.archtype == QL_ARCH.X8664:
            # struct user64_stat64 
            fstat64_buf += ql.pack32(fstat64_info.st_dev)                   # dev_t	 	st_dev
            fstat64_buf += ql.pack32(fstat64_info.st_mode)                  # mode_t	 	st_mode
            fstat64_buf += ql.pack32(fstat64_info.st_nlink)                 # nlink_t		st_nlink
            fstat64_buf += ql.pack32(fstat64_info.st_ino)                   # ino_t	  	st_ino
            fstat64_buf += ql.pack32(fstat64_info.st_uid)                   # uid_t		st_uid
            fstat64_buf += ql.pack32(fstat64_info.st_gid)                   # gid_t		st_gid
            fstat64_buf += ql.pack32(0x8800)                                # dev_t		st_rdev
            fstat64_buf += ql.pack32(int(fstat64_info.st_atime))            # user64_time_t	st_atime
            fstat64_buf += ql.pack32(0x0)                                   # user64_long_t	st_atimensec
            fstat64_buf += ql.pack32(int(fstat64_info.st_mtime))            # user64_time_t	st_mtime
            fstat64_buf += ql.pack32(0x0)                                   # user64_long_t	st_mtimensec
            fstat64_buf += ql.pack32(int(fstat64_info.st_ctime))            # user64_time_t	st_ctime
            fstat64_buf += ql.pack32(0x0)                                   # user64_long_t	st_ctimensec
            fstat64_buf += ql.pack32(0x0)                                   # user64_time_t	st_birthtime
            fstat64_buf += ql.pack32(0x0)                                   # user64_long_t	st_birthtimesec
            fstat64_buf += ql.pack32(fstat64_info.st_size)                  # off_t		st_size
            fstat64_buf += ql.pack32(0x0)                                   # blkcnt_t	st_blocks
            fstat64_buf += ql.pack32(0x0)                                   # blksize_t	st_blksize
            fstat64_buf += ql.pack32(0x0)                                   # __uint32_t	st_flags
            fstat64_buf += ql.pack32(0x0)                                   # __uint32_t	st_gen
            fstat64_buf += ql.pack32(0x0)                                   # __int32_t	st_lspare
            fstat64_buf += ql.pack32(0x0)                                   # __int64_t	st_qspare[2]
        else :
            raise QlErrorArch("[!] Arch not support in syscall fstat64")

        ql.mem.write(fstat64_add, fstat64_buf)
        regreturn = 0
    else:
        regreturn = -1

    ql.nprint("fstat64(%d, 0x%x) = %d" % (fstat64_fd, fstat64_add, regreturn))
    if regreturn == 0:
        ql.dprint(D_INFO, "[+] fstat64 write completed")
    else:
        ql.dprint(D_INFO, "[!] fstat64 read/write fail")
    ql.os.definesyscall_return(regreturn)

# 0x16e
def ql_syscall_bsdthread_register(ql, threadstart, wqthread, flags, stack_addr_hint, targetconc_ptr, dispatchqueue_offset):
    set_eflags_cf(ql, 0x0)
    ql.os.definesyscall_return(0x00000000400000df)

# 0x174
def ql_syscall_thread_selfid(ql, *args, **kw):
    thread_id = ql.os.macho_thread.id
    ql.nprint("thread_selfid() = %d" % (thread_id))
    ql.os.definesyscall_return(thread_id)

# 0x18e
def ql_syscall_open_nocancel(ql, filename, flags, mode, *args, **kw):
    path = ql.mem.string(filename)
    real_path = ql.os.transform_to_real_path(path)
    relative_path = ql.os.transform_to_relative_path(path)

    flags = flags & 0xffffffff
    mode = mode & 0xffffffff

    for i in range(256):
        if ql.os.file_des[i] == 0:
            idx = i
            break

    if idx == -1:
        regreturn = -1
    else:
        try:
            if ql.archtype== QL_ARCH.ARM:
                mode = 0

            flags = open_flags_mapping(flags, ql.archtype)
            ql.os.file_des[idx] = ql_file.open(real_path, flags, mode)
            regreturn = idx
        except:
            regreturn = -1

    ql.nprint("open(%s, 0x%s, 0x%x) = %d" % (relative_path, flags, mode, regreturn))
    if regreturn >= 0 and regreturn != 2:
        ql.dprint(D_INFO, "[+] File Found: %s" % relative_path)
    else:
        ql.dprint(D_INFO, "[!] File Not Found %s" % relative_path)
    ql.os.definesyscall_return(regreturn)

# 0x1b6
def ql_syscall_shared_region_map_and_slide_np(ql, fd, count, mappings_addr, slide, slide_start, slide_size):
    ql.nprint("shared_region_map_and_slide_np(%d, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)" % (
                fd, count ,mappings_addr, slide, slide_start, slide_size
            ))
    ql.dprint(D_INFO, "[+] shared_region_map_and_slide_np(fd: %d, count: 0x%x, mappings: 0x%x, slide: 0x%x, slide_start: 0x%x, slide_size: 0x%x)" % (
                fd, count ,mappings_addr, slide, slide_start, slide_size
            ))
    mapping_list = []
    for i in range(count):
        mapping = SharedFileMappingNp(ql)
        mapping.read_mapping(mappings_addr)
        ql.os.file_des[fd].lseek(mapping.sfm_file_offset)
        content = ql.os.file_des[fd].read(mapping.sfm_size)
        ql.mem.write(mapping.sfm_address, content)
        mappings_addr += mapping.size
        mapping_list.append(mapping)
    ql.os.definesyscall_return(slide_size)

# 0x1e3
def ql_syscall_csrctl(ql, op, useraddr, usersize, *args, **kw):
    ql.nprint("csrctl(0x%x, 0x%x, 0x%x)" % (op, useraddr, usersize))
    ql.dprint(D_INFO, "csrctl(op: 0x%x, useraddr :0x%x, usersize: 0x%x)" % (op, useraddr, usersize))
    ql.os.definesyscall_return(1)

# 0x1f4
def ql_syscall_getentropy(ql, buffer, size, *args, **kw):
    ql.nprint("getentropy(0x%x, 0x%x)" % (buffer, size))
    ql.dprint(D_INFO, "[+] getentropy(buffer: 0x%x, size: 0x%x)" % (buffer, size))
    ql.os.definesyscall_return(KERN_SUCCESS)

# 0x208
def ql_syscall_terminate_with_payload(ql, pid, reason_namespace, reason_code, payload, payload_size, reason_string):
    ql.nprint("terminate_with_payload(%d, 0x%x, 0x%x, 0x%x 0x%x, 0x%x)" % (
            pid, reason_namespace, reason_code,payload, payload_size, reason_string))

    ql.dprint(D_INFO, "[+] terminate_with_payload(pid: %d, reason_namespace: 0x%x, reason_code: 0x%x, payload: 0x%x \
            payload_size: 0x%x, reason_string: 0x%x)" % (pid, reason_namespace, reason_code,
            payload, payload_size, reason_string))
    ql.os.definesyscall_return(KERN_SUCCESS)
    ql.emu_stop()
    raise QlErrorSyscallError("[!] Exit with Error")

# 0x209
def ql_syscall_abort_with_payload(ql, reason_namespace, reason_code, payload, payload_size, reason_string, reason_flags):
    ql.nprint("abort_with_payload(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)" % (
            reason_namespace, reason_code, payload, payload_size, reason_string, reason_flags))

    ql.dprint(D_INFO, "[+] abort_with_payload(reason_namespace: 0x%x, reason_code: 0x%x, payload: 0x%x, payload_size: 0x%x, reason_string: 0x%x,\
            reason_flags: 0x%x)" % (reason_namespace, reason_code, payload, payload_size, reason_string, reason_flags))
    ql.os.definesyscall_return(KERN_SUCCESS)


################
# mdep syscall #
################

# 0x3d
# thread_set_tsd_base
def ql_x86_syscall_thread_fast_set_cthread_self64(ql, u_info_addr, *args, **kw):
    ql.dprint(D_INFO, "[+] [mdep] thread fast set cthread self64(tsd_base:0x%x)" % (u_info_addr))
    ql.reg.msr(GSMSR, u_info_addr)
    ql.os.definesyscall_return(KERN_SUCCESS)
    return 
