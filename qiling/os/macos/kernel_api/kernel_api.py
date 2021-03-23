#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes, struct

from time import time

from qiling.os.const import *
from qiling.os.macos.fncc import macos_kernel_api
from qiling.os.macos.structs import *
from qiling.os.macos.utils import gen_stub_code
from qiling.os.macos.events.macos_structs import *
from qiling.os.macos.events.macos_policy import *


@macos_kernel_api(passthru=True, params={
    "scope": POINTER,
})
def hook__kauth_unlisten_scope(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "mbuf": POINTER,
})
def hook__mbuf_pkthdr_header(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "mbuf": POINTER,
})
def hook__mbuf_type(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "amount": INT,
    "address": POINTER,
})
def hook__OSAddAtomic(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "mbuf": POINTER,
})
def hook__mbuf_pkthdr_len(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "dst": POINTER,
    "src": STRING,
    "s": SIZE_T,
    "chk_size": SIZE_T,
})
def hook____strlcpy_chk(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "mask": INT,
    "address": POINTER,
})
def hook__OSBitOrAtomic(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "address": POINTER,
})
def hook__OSDecrementAtomic(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "cred": POINTER,
})
def hook__kauth_cred_getgid(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "cred": POINTER,
})
def hook__kauth_cred_getuid(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "tvp": POINTER,
})
def hook__microtime(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "address": POINTER,
})
def hook__OSIncrementAtomic(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "b": POINTER,
    "c": INT,
    "len": SIZE_T,
})
def hook__memset(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "s": POINTER,
    "n": SIZE_T,
    "format": STRING,
})
def hook__snprintf(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "fmt": STRING,
    "argp": POINTER,
    "putc": POINTER,
    "arg": POINTER,
    "radix": INT,
    "is_log": INT,
})
def hook____doprnt(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "ch": INT,
    "arg": POINTER,
})
def hook__snprintf_func(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "dst": POINTER,
    "src": POINTER,
    "s": SIZE_T,
    "chk_size": SIZE_T,
})
def hook____memcpy_chk(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "s1": STRING,
    "s2": STRING,
})
def hook__strcmp(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "s1": STRING,
    "s2": STRING,
})
def hook__strprefix(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "s1": STRING,
    "s2": STRING,
    "n": SIZE_T
})
def hook__strncmp(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "s": STRING,
})
def hook__strlen(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "protocol": INT,
    "address": POINTER,
    "string": POINTER,
    "len": SIZE_T,
})
def hook__inet_ntop(ql, address, params):
    return

@macos_kernel_api(params={
    "format": STRING,
})
def hook__IOLog(ql, address, params):
    return

@macos_kernel_api(params={
    "format": STRING,
})
def hook__printf(ql, address, params):
    return 0

@macos_kernel_api(passthru=True, params={
    "dst0": POINTER,
    "length": SIZE_T,
})
def hook__bzero(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "p": POINTER,
    "uap": POINTER,
})
def hook__sysctlbyname(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "oidp": POINTER,
    "arg1": POINTER,
    "arg2": INT,
    "req": POINTER
})
def hook__sysctl_handle_string(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "req": POINTER,
    "p": POINTER,
    "l": SIZE_T,
})
def hook__sysctl_old_user(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "req": POINTER,
    "p": POINTER,
    "l": SIZE_T,
})
def hook__sysctl_new_user(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "oidp": POINTER,
    "arg1": POINTER,
    "arg2": INT,
    "req": POINTER,
})
def hook__sysctl_handle_int(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "req": POINTER,
    "bigValue": ULONGLONG,
    "valueSize": SIZE_T,
    "pValue": POINTER,
    "changed": POINTER,
})
def hook__sysctl_io_number(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "vp": POINTER,
    "uio": POINTER,
    "alp": POINTER,
    "options": ULONGLONG,
    "vap": POINTER,
    "fndesc": POINTER,
    "ctx": POINTER,
})
def hook__vfs_attr_pack(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "alp": POINTER,
    "vap": POINTER,
    "obj_type": INT,
    "fixedsize": POINTER,
    "is_64bit": INT,
    "use_fork": INT,
})
def hook__getattrlist_setupvattr_all(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "vp": POINTER,
    "auio": POINTER,
    "alp": POINTER,
    "options": ULONGLONG,
    "vap": POINTER,
    "fndesc": POINTER,
    "ctx": POINTER,
    "is_bulk": INT,
    "vtype": INT,
    "fixedsize": SIZE_T,
})
def hook__vfs_attr_pack_internal(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "asp": POINTER,
    "vap": POINTER,
    "use_fork": INT,
})
def hook__getattrlist_fixupattrs(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "ab": POINTER,
    "source": STRING,
    "count": SIZE_T,
})
def hook__attrlist_pack_string(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "src": POINTER,
    "dst": POINTER,
    "len": SIZE_T,
})
def hook__bcopy(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "dst": POINTER,
    "src": POINTER,
    "n": SIZE_T,
})
def hook__memcpy(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "c_cp": POINTER,
    "n": INT,
    "uio": POINTER,
})
def hook__uiomove64(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "kernel_addr": POINTER,
    "user_addr": POINTER,
    "nbytes": SIZE_T,
})
def hook__copyout(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "a_uio": POINTER,
    "a_count": SIZE_T,
})
def hook__uio_update(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "user_addr": POINTER,
    "kernel_addr": POINTER,
    "nbytes": SIZE_T,
})
def hook__copyin(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "dst": POINTER,
    "src": POINTER,
    "s": SIZE_T,
    "chk_size": SIZE_T,
})
def hook____memmove_chk(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "mbuf": POINTER,
})
def hook__mbuf_len(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "mbuf": POINTER,
})
def hook__mbuf_data(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "provider": POINTER,
})
def hook___ZN9IOService5startEPS_(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "provider": POINTER, 
    "score": POINTER,
})
def hook___ZN9IOService5probeEPS_Pi(ql, address, params):
    return

@macos_kernel_api(params={
    "size": SIZE_T,
})
def hook___ZN8OSObjectnwEm(ql, address, params):
    size = params["size"]
    addr = ql.os.heap.alloc(size)
    return addr

@macos_kernel_api(params={
    "this": POINTER,
})
def hook___ZN9IOServiceC2EPK11OSMetaClass(ql, address, params):
    return 0;

@macos_kernel_api(params={
    "this": POINTER,
})
def hook___ZNK11OSMetaClass19instanceConstructedEv(ql, address, params):
    return 0;

@macos_kernel_api(params={
    "this": POINTER,
    "option": POINTER,
})
def hook___ZN9IOService4initEP12OSDictionary(ql, address, params):
    return 1

@macos_kernel_api(params={

})
def hook___ZN9IOService15registerServiceEj(ql, address, params):
    return 0

@macos_kernel_api(params={
    "provider": POINTER,
})
def hook___ZN9IOService6attachEPS_(ql, address, params):
    return 1

@macos_kernel_api(params={
    "provider": POINTER,
})
def hook___ZN9IOService6detachEPS_(ql, address, params):
    return 0

@macos_kernel_api(params={
    "this": POINTER,
})
def hook___ZN12IOUserClientC2EPK11OSMetaClass(ql, address, params):
    return 0

@macos_kernel_api(params={
    "this": POINTER,
    "owningTask": UINT,
    "securityID": POINTER,
    "type": UINT,
    "properties": POINTER,
})
def hook___ZN12IOUserClient12initWithTaskEP4taskPvjP12OSDictionary(ql, address, params):
    return 1

@macos_kernel_api(params={
    "str": STRING,
    "flags": UINT,
})
def hook__OSMalloc_Tagalloc(ql, address, params):
    s = params["str"]
    flags = params["flags"]

    OSMTag_addr = ql.os.heap.alloc(ctypes.sizeof(OSMallocTag))
    OSMTag = OSMallocTag(ql, OSMTag_addr)

    if flags & 0x1:
        OSMTag._OSMT_attr = 0x1
    OSMTag.OSMT_refcnt = 0x1
    OSMTag.OSMT_name = s[:64].encode()
    OSMTag.OSMT_state = 0xDEAB0000
    OSMTag.OSMT_link = queue_entry(POINTER64(0), POINTER64(0))
    OSMTag.updateToMem()
    return OSMTag_addr

def lck_grp_init(ql, grp, s, attr):
    grp.lck_grp_name = s[:64].encode()
    grp.lck_grp_refcnt = 1;
    if attr is not None:
        grp.lck_grp_attr = attr.grp_attr_val
    else:
        grp.lck_grp_attr = 0

    grp.updateToMem()

@macos_kernel_api(params={
    "str": STRING,
    "attr": POINTER,
})
def hook__lck_grp_alloc_init(ql, address, params):
    s = params["str"]
    attr = params["attr"]

    grp_addr = ql.os.heap.alloc(ctypes.sizeof(lck_grp_t))
    grp = lck_grp_t(ql, grp_addr)
    if params["attr"] > 0:
        attr = lck_grp_attr_t(ql, params["attr"])
        attr.loadFromMem()
    else:
        attr = None
    lck_grp_init(ql, grp, s, attr)
    return grp_addr

@macos_kernel_api(params={
    "grp": POINTER,
    "grp_name": STRING,
    "attr": POINTER
})
def hook__lck_grp_init(ql, address, params):
    grp_name = params["grp_name"]
    attr = params["attr"]
    
    if params["grp"] > 0:
        grp = lck_grp_t(ql, params["grp"])
        grp.loadFromMem()
    else:
        grp = None

    if params["attr"] > 0:
        attr = lck_grp_attr_t(ql, params["attr"])
        attr.loadFromMem()
    else:
        attr = None

    lck_grp_init(ql, grp, grp_name, attr)

@macos_kernel_api(params={
    "grp": POINTER,
})
def hook__lck_grp_free(ql, address, params):
    ql.os.heap.free(params["grp"])
    return

# Values are taken from i386 locks.h
def lck_mtx_ext_init(ql, lck, grp, attr):
    if (attr.lck_attr_val) & 0x1:
        lck.lck_mtx_deb.type = 0x4d4d;
        lck.lck_mtx_attr |= 0x1;

    lck.lck_mtx_grp = grp;

    if grp.lck_grp_attr & 0x1:
        lck.lck_mtx_attr |= 0x2;

    lck.lck_mtx.lck_mtx_is_ext = 1;
    lck.lck_mtx.lck_mtx_pad32 = 0xFFFFFFFF;
    lck.updateToMem()

def lck_mtx_init(ql, lck, grp, attr):
    lck_ext = None
    lck_attr = None

    if attr != 0:
        lck_attr_addr = attr
    else:
        lck_attr_addr = ql.kernel_extrn_symbols_detail[b"LockDefaultLckAttr"]["n_value"]

    lck_attr = lck_attr_t(ql, lck_attr_addr)
    if (lck_attr.lck_attr_val) & 0x1:
        lck_ext_addr = ql.os.heap.alloc(ctypes.sizeof(lck_mtx_ext_t))
        lck_ext = lck_mtx_ext_t(ql, lck_ext_addr)
        lck_mtx_ext_init(ql, lck_ext, grp, lck_attr);   
        lck.lck_mtx_tag = 0x07ff1007;
        lck.lck_mtx_ptr = lck_ext;
        
    else:
        lck.lck_mtx_owner = 0;
        lck.lck_mtx_state = 0;
    
    lck.lck_mtx_pad32 = 0xFFFFFFFF;
    lck.updateToMem()

def lck_mtx_init_ext(ql, lck, lck_ext, grp, attr):
    if attr != 0:
        lck_attr_addr = attr
    else:
        lck_attr_addr = ql.kernel_extrn_symbols_detail[b"LockDefaultLckAttr"]["n_value"]

    lck_attr = lck_attr_t(ql, lck_attr_addr)
    if (lck_attr.lck_attr_val) & 0x1:
        lck_mtx_ext_init(ql, lck_ext, grp, lck_attr);   
        lck.lck_mtx_tag = 0x07ff1007;
        lck.lck_mtx_ptr = lck_ext;
    else:
        lck.lck_mtx_owner = 0;
        lck.lck_mtx_state = 0;
    
    lck.lck_mtx_pad32 = 0xFFFFFFFF;
    lck.updateToMem()


@macos_kernel_api(params={
    "lck": POINTER,
    "lck_ext": POINTER,
    "grp": POINTER,
    "attr": POINTER,
})
def hook__lck_mtx_init_ext(ql, address, params):
    lck = lck_mtx_t(ql, params["lck"])
    lck_ext = lck_mtx_ext_t(ql, params["lck_ext"])
    grp = lck_grp_t(ql, params["grp"])
    attr = lck_attr_t(ql, params["attr"])
    lck_mtx_init_ext(ql, lck, lck_ext, grp, attr)
    return


@macos_kernel_api(params={
    "lck": POINTER,
    "grp": POINTER,
    "attr": POINTER
})
def hook__lck_mtx_init(ql, address, params):
    lck = lck_mtx_t(ql, params["lck"])
    grp = lck_grp_t(ql, params["grp"])
    attr = lck_attr_t(ql, params["attr"])
    lck_mtx_init(ql, lck, grp, attr)
    return

@macos_kernel_api(params={
    "grp": POINTER,
    "attr": POINTER,
})
def hook__lck_mtx_alloc_init(ql, address, params):
    lck_addr = ql.os.heap.alloc(ctypes.sizeof(lck_mtx_t))
    lck = lck_mtx_t(ql, lck_addr)
    if params["grp"] > 0:
        grp = lck_grp_t(ql, params["grp"])
        grp.loadFromMem()
    else:
        grp = None

    if params["attr"] > 0:
        attr = lck_attr_t(ql, params["attr"])
        attr.loadFromMem()
    else:
        attr = None
    lck_mtx_init(ql, lck, grp, attr)
    return lck_addr

@macos_kernel_api(params={
    "lock": POINTER,
})
def hook__lck_mtx_lock(ql, address, params):
    return 1

@macos_kernel_api(params={
    "lock": POINTER,
})
def hook__lck_mtx_unlock(ql, address, params):
    return 1

@macos_kernel_api(params={

})
def hook__proc_list_lock(ql, address, params):
    return

@macos_kernel_api(params={

})
def hook__proc_list_unlock(ql, address, params):
    return

@macos_kernel_api(params={
    "size": SIZE_T,
    "tag": POINTER,
})
def hook__OSMalloc(ql, address, params):
    size = params["size"]
    addr = ql.os.heap.alloc(size)
    return addr

@macos_kernel_api(params={
    "addr": POINTER,
    "size": UINT,
    "tag": POINTER,
})
def hook__OSFree(ql, address, params):
    ql.os.heap.free(params["addr"])
    return


@macos_kernel_api(params={
    "psize": POINTER,
    "canblock": BOOL,
    "site": POINTER,
})
def hook__kalloc_canblock(ql, address, params):
    size, = struct.unpack("<Q", ql.mem.read(params["psize"], 8))
    addr = ql.os.heap.alloc(size)
    return addr

@macos_kernel_api(params={
    "data": POINTER,
    "size": SIZE_T,
})
def hook__kfree(ql, address, params):
    ql.os.heap.free(params["data"])
    return

@macos_kernel_api(params={
    "size": SIZE_T,
    "type": INT,
    "flags": INT,
})
def hook___MALLOC(ql, address, params):
    size = params["size"]
    addr = ql.os.heap.alloc(size)
    return addr

@macos_kernel_api(params={
    "addr": POINTER,
    "type": INT,
})
def hook___FREE(ql, address, params):
    ql.os.heap.free(params["addr"])
    return

@macos_kernel_api(params={
    "lock": POINTER
})
def hook__lck_rw_lock_exclusive(ql, address, params):
    return 1

@macos_kernel_api(params={
    "lock": POINTER
})
def hook__lck_rw_unlock_exclusive(ql, address, params):
    return 1

@macos_kernel_api(params={
    "lock": POINTER
})
def hook__lck_rw_done(ql, address, params):
    return 2

@macos_kernel_api(params={
    "oldValue": POINTER,
    "newValue": POINTER,
    "address": POINTER
})
def hook__OSCompareAndSwap(ql, address, params):
    addr = params["address"]
    oldValue = params["oldValue"]
    newValue = params["newValue"]
    cur_val, = struct.unpack("<I", ql.mem.read(addr, 4))
    if cur_val == oldValue:
        ql.mem.write(addr, struct.pack("<Q", newValue))
        return 1
    return 0

@macos_kernel_api(params={
    "lock": POINTER,
    "type": UINT
})
def hook__lck_mtx_assert(ql, address, params):
    return

@macos_kernel_api(passthru=True, params={
    "format": STRING,
})
def hook__panic(ql, address, params):
    return

@macos_kernel_api(params={
    "tv_sec": POINTER,
    "tv_usec": POINTER,
})
def hook__clock_get_calendar_microtime(ql, address, params):
    now = time()
    ql.mem.write(params["tv_sec"], struct.pack("<Q", int(now)))
    ql.mem.write(params["tv_usec"], struct.pack("<Q", int(round(now * 1000))))
    return

@macos_kernel_api(params={
    "buf": POINTER,
    "size": UINT
})
def hook__read_random(ql, address, params):
    ql.mem.write(params["buf"], struct.pack("<I", 0xdeadbeaf))
    return

@macos_kernel_api(params={
    "buf": POINTER,
    "size": UINT,
})
def hook__read_erandom(ql, address, params):
    ql.mem.write(params["buf"], struct.pack("<I", 0xdeadbeaf))
    return

COPYIN = 0      # from user virtual to kernel virtual
COPYOUT = 1     # from kernel virtual to user virtual
COPYINSTR = 2   # string variant of copyout
COPYINPHYS = 3  # from user virtual to kernel physical
COPYOUTPHYS = 4 # from kernel physical to user virtual
COPYINWORD = 5  # from user virtual to kernel virtual

@macos_kernel_api(params={
    "copy_type": INT,
    "user_addr": POINTER,
    "kernel_addr": POINTER,
    "nbytes": SIZE_T,
    "lencopied": POINTER,
    "use_kernel_map": INT
})
def hook__copyio(ql, address, params):
    copy_type = params["copy_type"]
    user_addr = params["user_addr"]
    kernel_addr = params["kernel_addr"]
    nbytes = params["nbytes"]

    # print("User: 0x%x --- kernel: (%s) 0x%x --- Size: %d" % (user_addr, type(kernel_addr), kernel_addr, nbytes))
    if copy_type in (COPYIN, COPYINSTR, COPYINPHYS, COPYINWORD):
        data = ql.mem.read(user_addr, nbytes)
        ql.mem.write(kernel_addr, bytes(data))
    else:
        data = ql.mem.read(kernel_addr, nbytes)
        ql.mem.write(user_addr, bytes(data))
    return 0

@macos_kernel_api(params={
    "addr": POINTER,
})
def hook__kfree_addr(ql, address, params):
    ql.os.heap.free(params["addr"])
    return

@macos_kernel_api(params={
    "addr": POINTER,
})
def hook__fuulong(ql, address, params):
    result = ql.mem.read(params["addr"], 8)
    return struct.unpack("<Q", result)[0]

@macos_kernel_api(params={
    "addr": POINTER,
    "uword": ULONGLONG,
})
def hook__suulong(ql, address, params):
    ql.mem.write(params["addr"], struct.pack("<Q", params["uword"]))
    return 0

@macos_kernel_api(params={

})
def hook__proc_selfpid(ql, address, params):
    return 0x1337

@macos_kernel_api(params={
    "pid": INT,
    "buf": POINTER,
    "size": INT,
})
def hook__proc_name(ql, address, params):
    # FIXME Why p_comm is only 50, but MAXPATHLEN is 1024??
    proc = ql.os.ev_manager.proc_find(params["pid"])

    if proc is not None:
        ql.mem.write(params["buf"], proc.p_comm)
    return

@macos_kernel_api(params={

})
def hook__proc_selfppid(ql, address, params):
    return 0x13371337

@macos_kernel_api(params={
    "pid": INT,
})
def hook__proc_find(ql, address, params):
    proc = ql.os.ev_manager.proc_find(params["pid"])
    if proc is not None:
        return proc.base
    return 0

@macos_kernel_api(params={
    "ctx": POINTER,
})
def hook__vfs_context_proc(ql, address, params):
    return params["ctx"]

@macos_kernel_api(params={
    "cred": POINTER,
    "uid": INT,
    "gid": INT
})
def hook__kauth_cred_setuidgid(ql, address, params):
    temp_pcred_addr = ql.os.heap.alloc(ctypes.sizeof(ucred_t))
    temp_pcred = ucred_t(ql, temp_pcred_addr)

    temp_pcred.cr_uid = params["uid"];
    temp_pcred.cr_ruid = params["uid"];
    temp_pcred.cr_svuid = params["uid"];
    # temp_pcred->cr_flags = pcred->cr_flags;
    # if (pcred->cr_flags & CRF_NOMEMBERD) {
    #     temp_pcred->cr_gmuid = KAUTH_UID_NONE;
    #     temp_pcred->cr_flags |= CRF_NOMEMBERD;
    # } else {
    #     temp_pcred->cr_gmuid = uid;
    #     temp_pcred->cr_flags &= ~CRF_NOMEMBERD;
    # }
    temp_pcred.cr_ngroups = 1;
    # /* displacing a supplementary group opts us out of memberd */
    # if (kauth_cred_change_egid(&temp_cred, gid)) {
    #     temp_pcred->cr_gmuid = KAUTH_UID_NONE;
    #     temp_pcred->cr_flags |= CRF_NOMEMBERD;
    # }
    temp_pcred.cr_rgid = params["gid"];
    temp_pcred.cr_svgid = params["gid"];
    # temp_cred.cr_label = cred->cr_label;
    temp_pcred.updateToMem()
    return temp_pcred_addr

@macos_kernel_api(params={
    "vp": POINTER,
    "pathbuf": POINTER,
    "len": POINTER,
})
def hook__vn_getpath(ql, address, params):
    vp = vnode_t(ql, params["vp"])
    vp = vp.loadFromMem()
    name = ql.mem.string(vp.v_name.value).encode()
    ql.mem.write(params["pathbuf"], name)
    ql.mem.write(params["len"], struct.pack("<I", len(name)))
    return 0

@macos_kernel_api(params={
    "continuation": POINTER,
    "params": POINTER,
    "new_thread": POINTER,
})
def hook__kernel_thread_start(ql, address, params):
    return 0

@macos_kernel_api(params={

})
def hook__kauth_getuid(ql, address, params):
    return ql.os.ev_manager.cred.cr_posix.cr_uid

@macos_kernel_api(params={

})
def hook__kauth_getgid(ql, address, params):
    return ql.os.ev_manager.cred.cr_posix.cr_rgid

@macos_kernel_api(params={

})
def hook__msleep(ql, address, params):
    return 0

@macos_kernel_api(params={
    "so": POINTER,
    "sockname": POINTER,
    "socknamelen": INT,
})
def hook__sock_getsockname(ql, address, params):
    real_so = ql.os.ev_manager.sockets[params["so"]]
    ql.mem.write(params["sockname"], bytes(real_so)[:params["socknamelen"]])
    return 0

@macos_kernel_api(params={
    "cmd": STRING,
})
def hook__KUNCExecute(ql, address, params):
    # ql.log.debug("Starting userspace process: %s" % params["cmd"])
    return 0

######################## Custom events / callbacks ########################

@macos_kernel_api(params={
    "oidp": POINTER
})
def hook__sysctl_register_oid(ql, address, params):
    oidp = sysctl_oid_t(ql, params["oidp"])
    oidp = oidp.loadFromMem()

    oid_name = ql.mem.string(oidp.oid_name.value)
    oid_parent = b""
    for symname, symb in ql.loader.kernel_extrn_symbols_detail.items():
        if symb["n_value"] == oidp.oid_parent.value:
            st = symname.find(b"sysctl_") + len("sysctl_")
            en = symname.find(b"_children", st)
            oid_parent = symname[st:en]
            break

    if len(oid_parent) == 0:
        # print("/!\\ Get symbol from local kext")
        for symname, symb in ql.loader.kext_local_symbols.items():
            # print("\tComparing for %s: 0x%x and 0x%x" %(symname, symb["n_value"] + ql.loader.loadbase, oidp.oid_parent.value))
            if symb["n_value"] + ql.loader.loadbase == oidp.oid_parent.value:
                st = symname.find(b"sysctl_") + len("sysctl_")
                en = symname.find(b"_children", st)
                oid_parent = symname[st:en]
                break

    if len(oid_parent) == 0:
        # print("/!\\ Get symbol from external kext")
        for symname, symb in ql.loader.kext_extern_symbols.items():
            # print("\tComparing for %s: 0x%x and 0x%x" %(symname, symb["n_value"] + ql.loader.loadbase, oidp.oid_parent.value))
            if symb["n_value"] + ql.loader.loadbase == oidp.oid_parent.value:
                st = symname.find(b"sysctl_") + len("sysctl_")
                en = symname.find(b"_children", st)
                oid_parent = symname[st:en]
                break


    true_name = oid_parent.lstrip(b"_") + b"." + oid_name.encode() + b"\x00"
    if oidp.oid_handler.value != 0:
        ql.log.debug("New sysctl callback has been registered: %s" % true_name)

        ql.os.ev_manager.register(oidp.oid_handler.value, true_name, MacOSEventType.EV_SYSCTL, ev_obj=oidp, idx=0)
    return

@macos_kernel_api(params={
    "oidp": POINTER
})
def hook__sysctl_unregister_oid(ql, address, params):
    oidp = sysctl_oid_t(ql, params["oidp"])
    oidp = oidp.loadFromMem()

    oid_name = ql.mem.string(oidp.oid_name.value)
    oid_parent = b""
    for symname, symb in ql.loader.kernel_extrn_symbols_detail.items():
        if symb["n_value"] == oidp.oid_parent.value:
            st = symname.find(b"sysctl_") + len("sysctl_")
            en = symname.find(b"_children", st)
            oid_parent = symname[st:en]
            break

    true_name = oid_parent.lstrip(b"_") + b"." + oid_name.encode() + b"\x00"
    ql.log.debug("A sysctl event has been deregistered: %s" % true_name)
    ql.os.ev_manager.deregister(true_name)

@macos_kernel_api(params={
    "from_kernel": BOOL,
    "string_is_canonical": BOOL,
    "namestring": POINTER,
    "namestringlen": SIZE_T,
    "name": POINTER,
    "namelen": INT,
    "req": POINTER,
})
def hook__sysctl_root(ql, address, params):
    if params["string_is_canonical"] == "True":
        ev_name = ql.mem.read(params["namestring"], params["namestringlen"]).decode()
        ev_type = MacOSEventType.EV_SYSCTL
        event = ql.os.ev_manager.get_event_by_name_and_type(ev_name, ev_type)
        if event is not None:
            obj = event.event
            ql.os.ev_manager.emit(ev_name, ev_type, [obj.oid_arg1.value, obj.oid_arg2, params["req"]])
        else:
            ql.log.debug("Event not found (%s, %s)" % (ev_name, ev_type.name))
    return 0

@macos_kernel_api(params={
    "userctl": POINTER,
    "ctlref": POINTER,
})
def hook__ctl_register(ql, address, params):
    userctl = kern_ctl_reg_t(ql, params["userctl"])
    userctl = userctl.loadFromMem()
    ctl_name = ql.mem.string(params["userctl"]).encode()
    flag = 0
    if userctl.ctl_connect.value != 0:
        flag |= 1 << 0
        ql.os.ev_manager.register(userctl.ctl_connect.value, ctl_name, MacOSEventType.EV_CTL_CONNECT, ev_obj=userctl, idx=0)
    if userctl.ctl_disconnect.value != 0:
        flag |= 1 << 1
        ql.os.ev_manager.register(userctl.ctl_disconnect.value, ctl_name, MacOSEventType.EV_CTL_DISCONNECT, ev_obj=userctl, idx=0)
    if userctl.ctl_send.value != 0:
        flag |= 1 << 2
        ql.os.ev_manager.register(userctl.ctl_send.value, ctl_name, MacOSEventType.EV_CTL_SEND, ev_obj=userctl, idx=0)
    if userctl.ctl_setopt.value != 0:
        flag |= 1 << 3
        ql.os.ev_manager.register(userctl.ctl_setopt.value, ctl_name, MacOSEventType.EV_CTL_SETOPT, ev_obj=userctl, idx=0)
    if userctl.ctl_getopt.value != 0:
        flag |= 1 << 4
        ql.os.ev_manager.register(userctl.ctl_getopt.value, ctl_name, MacOSEventType.EV_CTL_GETOPT, ev_obj=userctl, idx=0)
    if userctl.ctl_rcvd.value != 0:
        flag |= 1 << 5
        ql.os.ev_manager.register(userctl.ctl_rcvd.value, ctl_name, MacOSEventType.EV_CTL_RCVD_FUNC, ev_obj=userctl, idx=0)
    if userctl.ctl_send_list.value != 0:
        flag |= 1 << 6
        ql.os.ev_manager.register(userctl.ctl_send_list.value, ctl_name, MacOSEventType.EV_CTL_SEND_LIST_FUNC, ev_obj=userctl, idx=0)
    if userctl.ctl_bind.value != 0:
        flag |= 1 << 7
        ql.os.ev_manager.register(userctl.ctl_bind.value, ctl_name, MacOSEventType.EV_CTL_BIND_FUNC, ev_obj=userctl, idx=0)


    ql.log.debug("New ctl callbacks has been registered: %s (%d/%d/%d/%d/%d/%d/%d/%d)" % (
        ctl_name, 
        (flag & (1 << 0)) != 0,
        (flag & (1 << 1)) != 0,
        (flag & (1 << 2)) != 0,
        (flag & (1 << 3)) != 0,
        (flag & (1 << 4)) != 0,
        (flag & (1 << 5)) != 0,
        (flag & (1 << 6)) != 0,
        (flag & (1 << 7)) != 0))

    ql.mem.write(params["ctlref"], struct.pack("<Q", userctl.base))
    return 0

@macos_kernel_api(params={
    "ctlref": POINTER
})
def hook__ctl_deregister(ql, address, params):
    userctl = kern_ctl_reg_t(ql, params["userctl"])
    userctl = userctl.loadFromMem()
    ctl_name = ql.mem.string(params["userctl"]).encode()
    ql.log.debug("A ctl event has been deregistered: %s" % ctl_name)
    ql.os.ev_manager.deregister(ctl_name)

@macos_kernel_api(params={
    "filter": POINTER,
    "domain": INT,
    "type": INT,
    "protocol": INT
})
def hook__sflt_register(ql, address, params):
    sf = sflt_filter_t(ql, params["filter"])
    sf = sf.loadFromMem()
    true_name = str(sf.sf_handle).encode()
    true_name += b"_" + ql.mem.string(sf.sf_name.value).encode()
    true_name += b"_" + str(params["domain"]).encode()
    true_name += b"_" + str(params["type"]).encode()
    true_name += b"_" + str(params["protocol"]).encode()
    flag = 0

    if sf.sf_unregistered != 0:
        flag |= 1 << 0
        ql.os.ev_manager.register(sf.sf_unregistered.value, true_name, MacOSEventType.EV_SFLT_UNREGISTERED, protocol=params["protocol"])
    if sf.sf_attach != 0:
        flag |= 1 << 1
        ql.os.ev_manager.register(sf.sf_attach.value, true_name, MacOSEventType.EV_SFLT_ATTACH, protocol=params["protocol"])
    if sf.sf_detach != 0:
        flag |= 1 << 2
        ql.os.ev_manager.register(sf.sf_detach.value, true_name, MacOSEventType.EV_SFLT_DETACH, protocol=params["protocol"])
    if sf.sf_notify != 0:
        flag |= 1 << 3
        ql.os.ev_manager.register(sf.sf_notify.value, true_name, MacOSEventType.EV_SFLT_NOTIFY_CONNECTING, protocol=params["protocol"])
        ql.os.ev_manager.register(sf.sf_notify.value, true_name, MacOSEventType.EV_SFLT_NOTIFY_CONNECTED, protocol=params["protocol"])
        ql.os.ev_manager.register(sf.sf_notify.value, true_name, MacOSEventType.EV_SFLT_NOTIFY_DISCONNECTING, protocol=params["protocol"])
        ql.os.ev_manager.register(sf.sf_notify.value, true_name, MacOSEventType.EV_SFLT_NOTIFY_DISCONNECTED, protocol=params["protocol"])
        ql.os.ev_manager.register(sf.sf_notify.value, true_name, MacOSEventType.EV_SFLT_NOTIFY_FLUSH_READ, protocol=params["protocol"])
        ql.os.ev_manager.register(sf.sf_notify.value, true_name, MacOSEventType.EV_SFLT_NOTIFY_SHUTDOWN, protocol=params["protocol"])
        ql.os.ev_manager.register(sf.sf_notify.value, true_name, MacOSEventType.EV_SFLT_NOTIFY_CANTRECVMORE, protocol=params["protocol"])
        ql.os.ev_manager.register(sf.sf_notify.value, true_name, MacOSEventType.EV_SFLT_NOTIFY_CANTSENDMORE, protocol=params["protocol"])
        ql.os.ev_manager.register(sf.sf_notify.value, true_name, MacOSEventType.EV_SFLT_NOTIFY_CLOSING, protocol=params["protocol"])
        ql.os.ev_manager.register(sf.sf_notify.value, true_name, MacOSEventType.EV_SFLT_NOTIFY_BOUND, protocol=params["protocol"])
    if sf.sf_getpeername != 0:
        flag |= 1 << 4
        ql.os.ev_manager.register(sf.sf_getpeername.value, true_name, MacOSEventType.EV_SFLT_GETPEERNAME, protocol=params["protocol"])
    if sf.sf_getsockname != 0:
        flag |= 1 << 5
        ql.os.ev_manager.register(sf.sf_getsockname.value, true_name, MacOSEventType.EV_SFLT_GETSOCKNAME, protocol=params["protocol"])
    if sf.sf_data_in != 0:
        flag |= 1 << 6
        ql.os.ev_manager.register(sf.sf_data_in.value, true_name, MacOSEventType.EV_SFLT_DATA_IN, protocol=params["protocol"])
    if sf.sf_data_out != 0:
        flag |= 1 << 7
        ql.os.ev_manager.register(sf.sf_data_out.value, true_name, MacOSEventType.EV_SFLT_DATA_OUT, protocol=params["protocol"])
    if sf.sf_connect_in != 0:
        flag |= 1 << 8
        ql.os.ev_manager.register(sf.sf_connect_in.value, true_name, MacOSEventType.EV_SFLT_CONNECT_IN, protocol=params["protocol"])
    if sf.sf_connect_out != 0:
        flag |= 1 << 9
        ql.os.ev_manager.register(sf.sf_connect_out.value, true_name, MacOSEventType.EV_SFLT_CONNECT_OUT, protocol=params["protocol"])
    if sf.sf_bind != 0:
        flag |= 1 << 10
        ql.os.ev_manager.register(sf.sf_bind.value, true_name, MacOSEventType.EV_SFLT_BIND, protocol=params["protocol"])
    if sf.sf_setoption != 0:
        flag |= 1 << 11
        ql.os.ev_manager.register(sf.sf_setoption.value, true_name, MacOSEventType.EV_SFLT_SETOPTION, protocol=params["protocol"])
    if sf.sf_getoption != 0:
        flag |= 1 << 12
        ql.os.ev_manager.register(sf.sf_getoption.value, true_name, MacOSEventType.EV_SFLT_GETOPTION, protocol=params["protocol"])
    if sf.sf_listen != 0:
        flag |= 1 << 13
        ql.os.ev_manager.register(sf.sf_listen.value, true_name, MacOSEventType.EV_SFLT_LISTEN, protocol=params["protocol"])
    if sf.sf_ioctl != 0:
        flag |= 1 << 14
        ql.os.ev_manager.register(sf.sf_ioctl.value, true_name, MacOSEventType.EV_SFLT_IOCTL, protocol=params["protocol"])

    ql.log.debug("New sflt callbacks has been registered: %s (%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d)" % (
        true_name,
        (flag & (1 << 0)) != 0,
        (flag & (1 << 1)) != 0,
        (flag & (1 << 2)) != 0,
        (flag & (1 << 3)) != 0,
        (flag & (1 << 4)) != 0,
        (flag & (1 << 5)) != 0,
        (flag & (1 << 6)) != 0,
        (flag & (1 << 7)) != 0,
        (flag & (1 << 8)) != 0,
        (flag & (1 << 9)) != 0,
        (flag & (1 << 10)) != 0,
        (flag & (1 << 11)) != 0,
        (flag & (1 << 12)) != 0,
        (flag & (1 << 13)) != 0,
        (flag & (1 << 14)) != 0,))

    return 0

@macos_kernel_api(params={
    "handle": UINT,
})
def hook__sflt_unregister(ql, address, params):
    handle = str(params["handle"]).encode()

    evs = ql.os.ev_manager.get_events_by_name(b"", keyword=handle)
    for found in evs:
        ql.os.ev_manager.emit(found.name, MacOSEventType.EV_SFLT_UNREGISTERED, [params["handle"]])
        break

    ql.os.ev_manager.deregister(b"", keyword=handle)
    ql.log.debug("A sflt event has been deregistered: %s" % (handle))
    return 0

@macos_kernel_api(params={
    "mpc": POINTER,
    "handlep": POINTER,
    "xd": POINTER,
})
def hook__mac_policy_register(ql, address, params):
    mpc = mac_policy_conf_t(ql, params["mpc"])
    mpc = mpc.loadFromMem()

    mac_ops_addr = mpc.mpc_ops.value

    true_name = ql.mem.string(mpc.mpc_name.value).encode()
    for i in range(0, NUM_EVENT_MAC_POLICY):
        func, = struct.unpack("<Q", ql.mem.read(mac_ops_addr + i * 8, 8))
        if func != 0:
            ql.os.ev_manager.register(func, true_name, MACPolicy_EventType[MACPolicy_EventType(i + base_event_MAC).name])
            ql.log.debug("New mac policy callback has been registered: Name: %s --- Type: %s --- Addr: 0x%x " % 
                (true_name, MACPolicy_EventType(i + base_event_MAC).name, func))
            
    # Update mac_policy_list
    idx = ql.mac_policy_list.numloaded
    ql.mac_policy_list.numloaded += 1
    ql.mac_policy_list.updateToMem()

    if ql.mac_policy_list.entries.value != 0:
        entry = mac_policy_conf_t(ql, ql.mac_policy_list.entries.value)
        entry = entry.loadFromMem()

        while entry.mpc_list.value != 0:
            tmp = mac_policy_conf_t(ql, entry.mpc_list.value)
            tmp = tmp.loadFromMem()
            entry = tmp

        entry.mpc_list = POINTER64(params["mpc"])
        entry.updateToMem()
    else:
        ql.mac_policy_list.entries = POINTER64(params["mpc"])
        ql.mac_policy_list.updateToMem()

    ql.mem.write(params["handlep"], struct.pack("<I", idx))
    ql.policy_manager.bank[idx] = mpc.base

    # FIXME: Should place these before or after register?
    ql.os.ev_manager.emit_by_type(MACPolicy_EventType.EV_MAC_mpo_policy_init, [params["mpc"]])
    ql.os.ev_manager.emit_by_type(MACPolicy_EventType.EV_MAC_mpo_policy_initbsd, [params["mpc"]])
    
    return 0

@macos_kernel_api(params={
    "handle": POINTER
})
def hook__mac_policy_unregister(ql, address, params):
    handle = ql.policy_manager.bank[params["handle"]]
    mpc = mac_policy_conf_t(ql, handle)
    mpc = mpc.loadFromMem()

    ql.os.ev_manager.emit_by_type(MACPolicy_EventType.EV_MAC_mpo_policy_destroy, [mpc.base])

    true_name = ql.mem.string(mpc.mpc_name.value).encode()
    ql.os.ev_manager.deregister(true_name)
    del ql.policy_manager.bank[params["handle"]]

    # Update mac_policy_list
    entry = mac_policy_conf_t(ql, ql.mac_policy_list.entries.value)
    entry = entry.loadFromMem()

    if entry.base != handle:
        while entry.mpc_list.value != handle:
            tmp = mac_policy_conf_t(ql, entry.mpc_list.value)
            tmp = tmp.loadFromMem()
            entry = tmp

        entry.mpc_list = POINTER64(mpc.mpc_list.value)
    else:
        ql.mac_policy_list.entries = POINTER64(0)

    ql.log.debug("A MAC event has been deregistered: 0x%x" % handle)
    return 0;

@macos_kernel_api(params={
    "_identifier": POINTER,
    "_callback": POINTER,
    "_idata": POINTER,
})
def hook__kauth_listen_scope(ql, address, params):
    ev_name = ql.mem.string(params["_identifier"]).replace("com.", "").replace("apple.", "").upper().replace(".", "_")
    ql.os.ev_manager.register(params["_callback"], ev_name.encode(), MacOSEventType["EV_" + ev_name])
    ql.log.debug("New kauth callback has been registered: %s" % ev_name)
    return params["_identifier"]

@macos_kernel_api(params={
    "filter": POINTER,
    "filter_ref": POINTER,
})
def hook__ipf_addv4(ql, address, params):
    ip_filter_ipv4 = ipf_filter_t(ql, params["filter"]).loadFromMem()
    flag = 0
    name = ql.mem.string(ip_filter_ipv4.name.value).encode() + b"_ipf"
    cookie = ip_filter_ipv4.cookie.value

    ql.os.ev_manager.ipf_cookie[name] = cookie

    if ip_filter_ipv4.ipf_input.value > 0:
        flag |= (1 << 0)
        ql.os.ev_manager.register(ip_filter_ipv4.ipf_input.value, name, MacOSEventType.EV_IPF_INPUT)

    if ip_filter_ipv4.ipf_output.value > 0:
        flag |= (1 << 1)
        ql.os.ev_manager.register(ip_filter_ipv4.ipf_output.value, name, MacOSEventType.EV_IPF_OUTPUT)

    if ip_filter_ipv4.ipf_detach.value > 0:
        flag |= (1 << 2)
        ql.os.ev_manager.register(ip_filter_ipv4.ipf_detach.value, name, MacOSEventType.EV_IPF_DETACH)

    ql.log.debug("New ipf callbacks has been registered: %s (%d/%d/%d)" % (
        name,
        (flag & (1 << 0)) != 0,
        (flag & (1 << 1)) != 0,
        (flag & (1 << 2)) != 0,
        ))

    ql.mem.write(params["filter_ref"], struct.pack("<Q", ip_filter_ipv4.base))
    return 0;


##################################################################

########################## Syscall ###############################

@macos_kernel_api(params={
    "p": POINTER,
    "getattrlistbulk_args": POINTER,
    "retval": POINTER,
})
def hook__getattrlistbulk(ql, address, params):
    getattrlistbulk_args = getattrlistbulk_args_t(ql, params["getattrlistbulk_args"]).loadFromMem()
    dirfd = ql.os.ev_manager.map_fd[getattrlistbulk_args.dirfd]

    vfs_attr_pack = ql.loader.kernel_extrn_symbols_detail[b"_vfs_attr_pack"]["n_value"]

    uiovp_addr = ql.os.heap.alloc(ctypes.sizeof(user_iovec_t))
    uiovp = user_iovec_t(ql, uiovp_addr)
    uiovp.iov_base = getattrlistbulk_args.attributeBuffer
    uiovp.iov_len = getattrlistbulk_args.bufferSize
    uiovp.updateToMem()

    uio_addr = ql.os.heap.alloc(ctypes.sizeof(uio_t))
    uio = uio_t(ql, uio_addr)
    uio.uio_iovs = iovecs_t(kiovp=POINTER64(uiovp_addr), uiovp=POINTER64(uiovp_addr))
    uio.uio_iovcnt = 1
    uio.uio_offset = 0
    uio.uio_segflg = 8 # UIO_USERSPACE64
    uio.uio_rw = 0 # UIO_READ
    uio.uio_resid_64 = getattrlistbulk_args.bufferSize
    uio.uio_size = 72
    uio.uio_max_iovs = 1
    uio.uio_flags = 1
    uio.updateToMem()

    result = 0
    for path in dirfd.iterdir():
        result += 1
    ql.mem.write(params["retval"], struct.pack("<Q", result))

    for path in dirfd.iterdir():
        info = path.stat()

        vap_addr = ql.os.heap.alloc(ctypes.sizeof(vnode_attr_t))
        vap = vnode_attr_t(ql, vap_addr)
        vap.va_supported = 51573293058
        vap.va_active = 51573293058
        vap.va_nlink = info.st_nlink

        vap.va_total_size = info.st_size
        vap.va_data_size = info.st_size
        vap.va_uid = info.st_uid
        vap.va_gid = info.st_gid
        vap.va_mode = info.st_mode
        vap.va_fileid = info.st_ino
        vap.va_devid = info.st_dev
        vap.va_create_time = timespec_t(tv_sec = int(info.st_ctime), tv_nsec = info.st_ctime_ns % 1000000)
        vap.va_access_time = timespec_t(tv_sec = int(info.st_atime), tv_nsec = info.st_atime_ns % 1000000)
        vap.va_modify_time = timespec_t(tv_sec = int(info.st_mtime), tv_nsec = info.st_mtime_ns % 1000000)
        truename = path.name + "\x00"
        vap.va_name = POINTER64(ql.os.heap.alloc(1024))
        ql.mem.write(vap.va_name.value, truename.encode())
        vap.updateToMem()

        code = gen_stub_code(ql, [0, uio.base, getattrlistbulk_args.alist, getattrlistbulk_args.options, vap.base, 0, params["p"]], vfs_attr_pack)
        print("Trampoline created at 0x%x for %s (0x%x) and 0x%x" % (code, truename, vap.va_name.value, vap.base))
        ql.stack_push(code)

    return



##################################################################
