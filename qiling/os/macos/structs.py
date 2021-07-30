#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes, struct

from enum import IntEnum


class POINTER64(ctypes.Structure):
    _fields_ = [("value", ctypes.c_uint64)]

class list_entry(ctypes.Structure):
    _fields_ = (
        ("le_next", POINTER64),
        ("le_prev", POINTER64),
    )

class list_head(ctypes.Structure):
    _fields_ = (
        ("lh_first", POINTER64),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

class tailq_head(ctypes.Structure):
    _fields_ = (
        ("tqh_first", POINTER64),
        ("tqh_last", POINTER64),
    )

class slist_head(ctypes.Structure):
    _fields_ = (
        ("slh_first", POINTER64),
    )

class tailq_entry(ctypes.Structure):
    _fields_ = (
        ("tqe_next", POINTER64),
        ("tqe_prev", POINTER64),
    )

# struct IOExternalMethodArguments
# {
#     uint32_t      version;

#     uint32_t      selector;

#     mach_port_t           asyncWakePort;
#     io_user_reference_t * asyncReference;
#     uint32_t              asyncReferenceCount;

#     const uint64_t *    scalarInput;
#     uint32_t      scalarInputCount;

#     const void *  structureInput;
#     uint32_t      structureInputSize;

#     IOMemoryDescriptor * structureInputDescriptor;
   
#     uint64_t *        scalarOutput;
#     uint32_t      scalarOutputCount;

#     void *        structureOutput;
#     uint32_t      structureOutputSize;

#     IOMemoryDescriptor * structureOutputDescriptor;
#     uint32_t       structureOutputDescriptorSize;

#     uint32_t      __reservedA;

#     OSObject **         structureVariableOutputData;

#     uint32_t      __reserved[30];
# };

class IOExternalMethodArguments(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ("_version", ctypes.c_uint32),
        ("_selector", ctypes.c_uint32),
        ("_asyncWakePort", ctypes.c_uint32),
        ("_asyncReference", POINTER64),
        ("_asyncReferenceCount", ctypes.c_uint32),
        ("_scalarInput", POINTER64),
        ("_scalarInputCount", ctypes.c_uint32),
        ("_structureInput", POINTER64),
        ("_structureInputSize", ctypes.c_uint32),
        ("_structureInputDescriptor", POINTER64),
        ("_scalarOutput", POINTER64),
        ("_scalarOutputCount", ctypes.c_uint32),
        ("_structureOutput", POINTER64),
        ("_structureOutputSize", ctypes.c_uint32),
        ("_structureOutputDescriptor", POINTER64),
        ("_structureOutputDescriptorSize", ctypes.c_uint32),
        ("___reservedA", ctypes.c_uint32),
        ("_structureVariableOutputData", POINTER64),
        ("___reserved", ctypes.c_uint32 * 30)
    )
    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    @property
    def scalarInput(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        array = self.ql.mem.read(obj._scalarInput.value, obj._scalarInputCount)
        return [struct.unpack("<Q", array[i: i + 8]) for i in range(0, len(array), 8)]

    @property
    def structureInput(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        return self.ql.mem.read(obj._structureInput.value, obj._structureInputSize)

    @property
    def scalarOutput(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        array = self.ql.mem.read(obj._scalarOutput.value, obj._scalarOutputCount)
        return [struct.unpack("<Q", array[i: i + 8]) for i in range(0, len(array), 8)]

    @property
    def structureOutput(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        obj = type(self).from_buffer(data)
        return self.ql.mem.read(obj._structureOutput.value, obj._structureOutputSize)

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# typedef IOReturn (*IOExternalMethodAction)(OSObject * target, void * reference, 
#                         IOExternalMethodArguments * arguments);
# struct IOExternalMethodDispatch
# {
#     IOExternalMethodAction function;
#     uint32_t           checkScalarInputCount;
#     uint32_t           checkStructureInputSize;
#     uint32_t           checkScalarOutputCount;
#     uint32_t           checkStructureOutputSize;
# };

class IOExternalMethodDispatch(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ("function", POINTER64),
        ("checkScalarInputCount", ctypes.c_uint32),
        ("checkStructureInputSize", ctypes.c_uint32),
        ("checkScalarOutputCount", ctypes.c_uint32),
        ("checkStructureOutputSize", ctypes.c_uint32)
    )
    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# typedef struct kmod_info {
#     struct kmod_info  * next;
#     int32_t             info_version;           // version of this structure
#     uint32_t            id;
#     char                name[KMOD_MAX_NAME];
#     char                version[KMOD_MAX_NAME];
#     int32_t             reference_count;        // # linkage refs to this 
#     kmod_reference_t  * reference_list;         // who this refs (links on)
#     vm_address_t        address;                // starting address
#     vm_size_t           size;                   // total size
#     vm_size_t           hdr_size;               // unwired hdr size
#     kmod_start_func_t * start;
#     kmod_stop_func_t  * stop;
# } kmod_info_t;

class kmod_info_t(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ("next", POINTER64),
        ("info_version", ctypes.c_int32),
        ("id", ctypes.c_uint32),
        ("name", ctypes.c_char * 64),
        ("version", ctypes.c_char * 64),
        ("reference_count", ctypes.c_int32),
        ("reference_list", POINTER64),
        ("address", POINTER64),
        ("size", ctypes.c_uint64),
        ("hdr_size", ctypes.c_uint64),
        ("start", POINTER64),
        ("stop", POINTER64)
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# struct queue_entry {
#     struct queue_entry  *next;      /* next element */
#     struct queue_entry  *prev;      /* previous element */
# };

class queue_entry(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ("next", POINTER64),
        ("prev", POINTER64)
    )

# typedef struct _OSMallocTag_ {
#     queue_chain_t   OSMT_link;
#     uint32_t        OSMT_refcnt;
#     uint32_t        OSMT_state;
#     uint32_t        OSMT_attr;
#     char            OSMT_name[OSMT_MAX_NAME];
# }

class OSMallocTag(ctypes.Structure):
    _pack_ = 8
    _fields_ = (
        ("OSMT_link", queue_entry),
        ("OSMT_refcnt", ctypes.c_uint32),
        ("OSMT_state", ctypes.c_uint32),
        ("OSMT_attr", ctypes.c_uint32),
        ("OSMT_name", ctypes.c_char * 64)
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# typedef struct {
#     uint64_t            lck_grp_spin_util_cnt;
#     uint64_t            lck_grp_spin_held_cnt;
#     uint64_t            lck_grp_spin_miss_cnt;
#     uint64_t            lck_grp_spin_held_max;
#     uint64_t            lck_grp_spin_held_cum;
# } lck_grp_spin_stat_t;

# typedef struct {
#     uint64_t            lck_grp_mtx_util_cnt;
#     /* On x86, this is used as the "direct wait" count */
#     uint64_t            lck_grp_mtx_held_cnt;
#     uint64_t            lck_grp_mtx_miss_cnt;
#     uint64_t            lck_grp_mtx_wait_cnt;
#     /* Rest currently unused */
#     uint64_t            lck_grp_mtx_held_max;
#     uint64_t            lck_grp_mtx_held_cum;
#     uint64_t            lck_grp_mtx_wait_max;
#     uint64_t            lck_grp_mtx_wait_cum;
# } lck_grp_mtx_stat_t;

# typedef struct {
#     uint64_t            lck_grp_rw_util_cnt;
#     uint64_t            lck_grp_rw_held_cnt;
#     uint64_t            lck_grp_rw_miss_cnt;
#     uint64_t            lck_grp_rw_wait_cnt;
#     uint64_t            lck_grp_rw_held_max;
#     uint64_t            lck_grp_rw_held_cum;
#     uint64_t            lck_grp_rw_wait_max;
#     uint64_t            lck_grp_rw_wait_cum;
# } lck_grp_rw_stat_t;

# typedef struct _lck_grp_stat_ {
#     lck_grp_spin_stat_t lck_grp_spin_stat;
#     lck_grp_mtx_stat_t  lck_grp_mtx_stat;
#     lck_grp_rw_stat_t   lck_grp_rw_stat;
# } lck_grp_stat_t;

# typedef struct _lck_grp_ {
#     queue_chain_t       lck_grp_link;
#     uint32_t        lck_grp_refcnt;
#     uint32_t        lck_grp_spincnt;
#     uint32_t        lck_grp_mtxcnt;
#     uint32_t        lck_grp_rwcnt;
#     uint32_t        lck_grp_attr;
#     char            lck_grp_name[LCK_GRP_MAX_NAME];
#     lck_grp_stat_t      lck_grp_stat;
# } lck_grp_t;

class lck_grp_spin_stat_t(ctypes.Structure):
    _fields_ = (
        ("lck_grp_spin_util_cnt", ctypes.c_uint64),
        ("lck_grp_spin_held_cnt", ctypes.c_uint64),
        ("lck_grp_spin_miss_cnt", ctypes.c_uint64),
        ("lck_grp_spin_held_max", ctypes.c_uint64),
        ("lck_grp_spin_held_cum", ctypes.c_uint64),
    )

class lck_grp_mtx_stat_t(ctypes.Structure):
    _fields_ = (
        ("lck_grp_mtx_util_cnt", ctypes.c_uint64),
        ("lck_grp_mtx_held_cnt", ctypes.c_uint64),
        ("lck_grp_mtx_miss_cnt", ctypes.c_uint64),
        ("lck_grp_mtx_wait_cnt", ctypes.c_uint64),
        ("lck_grp_mtx_held_max", ctypes.c_uint64),
        ("lck_grp_mtx_held_cum", ctypes.c_uint64),
        ("lck_grp_mtx_wait_max", ctypes.c_uint64),
        ("lck_grp_mtx_wait_cum", ctypes.c_uint64),
    )

class lck_grp_rw_stat_t(ctypes.Structure):
    _fields_ = (
        ("lck_grp_rw_util_cnt", ctypes.c_uint64),
        ("lck_grp_rw_held_cnt", ctypes.c_uint64),
        ("lck_grp_rw_miss_cnt", ctypes.c_uint64),
        ("lck_grp_rw_wait_cnt", ctypes.c_uint64),
        ("lck_grp_rw_held_max", ctypes.c_uint64),
        ("lck_grp_rw_held_cum", ctypes.c_uint64),
        ("lck_grp_rw_wait_max", ctypes.c_uint64),
        ("lck_grp_rw_wait_cum", ctypes.c_uint64),
    )

class lck_grp_stat_t(ctypes.Structure):
    _fields_ = (
        ("lck_grp_spin_stat", lck_grp_spin_stat_t),
        ("lck_grp_mtx_stat", lck_grp_mtx_stat_t),
        ("lck_grp_rw_stat", lck_grp_rw_stat_t),
    )

class lck_grp_t(ctypes.Structure):
    _fields_ = (
        ("lck_grp_link", queue_entry),
        ("lck_grp_refcnt", ctypes.c_uint32),
        ("lck_grp_spincnt", ctypes.c_uint32),
        ("lck_grp_mtxcnt", ctypes.c_uint32),
        ("lck_grp_rwcnt", ctypes.c_uint32),
        ("lck_grp_attr", ctypes.c_uint32),
        ("lck_grp_name", ctypes.c_char * 64),
        ("lck_grp_stat", lck_grp_stat_t)
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# typedef struct _lck_grp_attr_ {
#     uint32_t    grp_attr_val;
# } lck_grp_attr_t;

class lck_grp_attr_t(ctypes.Structure):
    _fields_ = (
        ("grp_attr_val", ctypes.c_uint32),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# typedef struct _lck_attr_ {
#     unsigned int    lck_attr_val;
# } lck_attr_t;

class lck_attr_t(ctypes.Structure):
    _fields_ = (
        ("lck_attr_val", ctypes.c_uint32),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# typedef struct _lck_mtx_ {
#     union {
#         struct {
#             volatile uintptr_t      lck_mtx_owner;
#             union {
#                 struct {
#                     volatile uint32_t
#                         lck_mtx_waiters:16,
#                         lck_mtx_pri:8,
#                         lck_mtx_ilocked:1,
#                         lck_mtx_mlocked:1,
#                         lck_mtx_promoted:1,
#                         lck_mtx_spin:1,
#                         lck_mtx_is_ext:1,
#                         lck_mtx_pad3:3;
#                 };
#                     uint32_t    lck_mtx_state;
#             };
#             /* Pad field used as a canary, initialized to ~0 */
#             uint32_t            lck_mtx_pad32;
#         };
#         struct {
#             struct _lck_mtx_ext_        *lck_mtx_ptr;
#             uint32_t            lck_mtx_tag;
#             uint32_t            lck_mtx_pad32_2;
#         };
#     };
# } lck_mtx_t;

class lck_mtx_t(ctypes.Structure):
    class lck_mtx_tmp_union(ctypes.Union):
        class lck_mtx_tmp_union_struct_1(ctypes.Structure):
            class lck_mtx_tmp_union_struct_union(ctypes.Union):
                class lck_mtx_tmp_union_struct_union_struct(ctypes.Structure):
                    _fields_ = [
                        ("lck_mtx_waiters", ctypes.c_uint32, 16),
                        ("lck_mtx_pri", ctypes.c_uint32, 8),
                        ("lck_mtx_ilocked", ctypes.c_uint32, 1),
                        ("lck_mtx_mlocked", ctypes.c_uint32, 1),
                        ("lck_mtx_promoted", ctypes.c_uint32, 1),
                        ("lck_mtx_spin", ctypes.c_uint32, 1),
                        ("lck_mtx_is_ext", ctypes.c_uint32, 1),
                        ("lck_mtx_pad3", ctypes.c_uint32, 3)
                    ]
                _anonymous_ = ("tmp_struct", )
                _fields_ = (
                    ("tmp_struct", lck_mtx_tmp_union_struct_union_struct),
                    ("lck_mtx_state", ctypes.c_uint32)
                )
            _anonymous_ = ("tmp_union", )
            _fields_ = (
                ("lck_mtx_owner", ctypes.c_uint64),
                ("tmp_union", lck_mtx_tmp_union_struct_union),
                ("lck_mtx_pad32", ctypes.c_uint32)
            )

        class lck_mtx_tmp_union_struct_2(ctypes.Structure):
            _fields_ = (
                ("lck_mtx_ptr", POINTER64),
                ("lck_mtx_tag", ctypes.c_uint32),
                ("lck_mtx_pad32_2", ctypes.c_uint32)
            )

        _anonymous_ = ("tmp_struct_1", "tmp_struct_2", )
        _fields_ = (
            ("tmp_struct_1", lck_mtx_tmp_union_struct_1),
            ("tmp_struct_2", lck_mtx_tmp_union_struct_2),
        )
    _anonymous_ = ("tmp_union", )
    _fields_ = (
        ("tmp_union", lck_mtx_tmp_union),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# typedef struct {
#     unsigned int        type;
#     unsigned int        pad4;
#     vm_offset_t     pc;
#     vm_offset_t     thread;
# } lck_mtx_deb_t;

class lck_mtx_deb_t(ctypes.Structure):
    _fields_ = (
        ("type", ctypes.c_uint32),
        ("pad4", ctypes.c_uint32),
        ("pc", ctypes.c_uint64),
        ("thread", ctypes.c_uint64)
    )

# typedef struct _lck_mtx_ext_ {
#     lck_mtx_t       lck_mtx;
#     struct _lck_grp_    *lck_mtx_grp;
#     unsigned int        lck_mtx_attr;
#     unsigned int        lck_mtx_pad1;
#     lck_mtx_deb_t       lck_mtx_deb;
#     uint64_t        lck_mtx_stat;
#     unsigned int        lck_mtx_pad2[2];
# } lck_mtx_ext_t;

class lck_mtx_ext_t(ctypes.Structure):
    _fields_ = (
        ("lck_mtx", lck_mtx_t),
        ("lck_mtx_grp", POINTER64),
        ("lck_mtx_attr", ctypes.c_uint32),
        ("lck_mtx_pad1", ctypes.c_uint32),
        ("lck_mtx_deb", lck_mtx_deb_t),
        ("lck_mtx_stat", ctypes.c_uint64),
        ("lck_mtx_pad2", ctypes.c_uint32 * 2)
    )
    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# struct kauth_listener {
#     TAILQ_ENTRY(kauth_listener) kl_link;
#     const char *                kl_identifier;
#     kauth_scope_callback_t      kl_callback;
#     void *                      kl_idata;
# };

class kauth_listener_t(ctypes.Structure):
    class kauth_listener_struct(ctypes.Structure):
        _fields_ = (
            ("tqe_next", POINTER64),
            ("tqe_prev", POINTER64),
        )
    _fields_ = (
        ("kl_link", kauth_listener_struct),
        ("kl_identifier", POINTER64),
        ("kl_callback", POINTER64),
        ("kl_idata", POINTER64)
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# struct kauth_local_listener {
#     kauth_listener_t            kll_listenerp;
#     kauth_scope_callback_t      kll_callback;
#     void *                      kll_idata;
# };

class kauth_local_listener_t(ctypes.Structure):
    _fields_ = (
        ("kll_listenerp", kauth_listener_t),
        ("kll_callback", POINTER64),
        ("kll_idata", POINTER64),
    )

# struct kauth_scope {
#     TAILQ_ENTRY(kauth_scope)    ks_link;
#     volatile struct kauth_local_listener  ks_listeners[KAUTH_SCOPE_MAX_LISTENERS];
#     const char *                ks_identifier;
#     kauth_scope_callback_t      ks_callback;
#     void *                      ks_idata;
#     u_int                       ks_flags;
# };

class kauth_scope(ctypes.Structure):
    class kauth_scope_struct(ctypes.Structure):
        _fields_ = (
            ("tqe_next", POINTER64),
            ("tqe_prev", POINTER64),
        )
    _fields_ = (
        ("ks_link", kauth_scope_struct),
        ("ks_listeners", kauth_local_listener_t * 15),
        ("ks_identifier", POINTER64),
        ("ks_callback", POINTER64),
        ("ks_idata", POINTER64),
        ("ks_flags", ctypes.c_uint32)
    )
    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# struct domain {
#     int dom_family;     /* AF_xxx */
#     uint32_t dom_flags;     /* domain flags (see below ) */
#     uint32_t dom_refs;      /* # socreates outstanding */
#     lck_mtx_t *dom_mtx;     /* domain global mutex */
#     decl_lck_mtx_data(, dom_mtx_s);
#     TAILQ_ENTRY(domain) dom_entry;  /* next domain in list */
#     TAILQ_HEAD(, protosw) dom_protosw; /* protosw chain */
#     void    (*dom_init)     /* initialize domain data structures */
#             (struct domain *);
#     int (*dom_externalize)  /* externalize access rights */
#             (struct mbuf *);
#     void    (*dom_dispose)      /* dispose of internalized rights */
#             (struct mbuf *);
#     int (*dom_rtattach)     /* initialize routing table */
#             (void **, int);
#     int dom_rtoffset;       /* an arg to rtattach, in bits */
#     int dom_maxrtkey;       /* for routing layer */
#     int dom_protohdrlen;    /* len of protocol header */
#     const char *dom_name;
#     struct domain_old *dom_old; /* domain pointer per net_add_domain */
# };

class domain_t(ctypes.Structure):
    class domain_struct(ctypes.Structure):
        _fields_ = (
            ("tqe_next", POINTER64),
            ("tqe_prev", POINTER64),
        )

    _fields_ = (
        ("dom_family", ctypes.c_int32),
        ("dom_flags", ctypes.c_uint32),
        ("dom_refs", ctypes.c_uint32),
        ("dom_mtx", POINTER64),
        ("dom_mtx_s", lck_mtx_t),
        ("dom_entry", domain_struct),
        ("dom_protosw", tailq_head),
        ("dom_init", POINTER64),
        ("dom_externalize", POINTER64),
        ("dom_dispose", POINTER64),
        ("dom_rtattach", POINTER64),
        ("dom_rtoffset", ctypes.c_int32),
        ("dom_maxrtkey", ctypes.c_int32),
        ("dom_protohdrlen", ctypes.c_int32),
        ("dom_name", POINTER64),
        ("dom_old", POINTER64)
    )
    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

    def dump(self):
        for field in self._fields_:
            self.ql.log.info(field[0], getattr(self, field[0]))

# struct kev_d_vectors {
#     u_int32_t   data_length;    /* Length of the event data */
#     void        *data_ptr;  /* Pointer to event data */
# };

# /*!
#     @struct kev_msg
#     @discussion This structure is used when posting a kernel event.
#     @field vendor_code The vendor code assigned by kev_vendor_code_find.
#     @field kev_class The event's class.
#     @field kev_class The event's subclass.
#     @field kev_class The event's code.
#     @field dv An array of vectors describing additional data to be appended
#         to the kernel event.
#  */
# struct kev_msg {
#     u_int32_t vendor_code;      /* For non-Apple extensibility */
#     u_int32_t kev_class;        /* Layer of event source */
#     u_int32_t kev_subclass;     /* Component within layer */
#     u_int32_t event_code;       /* The event code */
#     struct kev_d_vectors dv[N_KEV_VECTORS]; /* Up to n data vectors */
# };

class kev_d_vectors(ctypes.Structure):
    _fields_ = (
        ("data_length", ctypes.c_uint32),
        ("data_ptr", POINTER64),
    )

class kev_msg(ctypes.Structure):
    _fields_ = (
        ("vendor_code", ctypes.c_uint32),
        ("kev_class", ctypes.c_uint32),
        ("kev_subclass", ctypes.c_uint32),
        ("event_code", ctypes.c_uint32),
        ("dv", kev_d_vectors * 5)
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

    def dump(self):
        for field in self._fields_:
            self.ql.log.info(field[0], getattr(self, field[0]))

# struct nlist_64 {
#     union {
#         uint32_t  n_strx; /* index into the string table */
#     } n_un;
#     uint8_t n_type;        /* type flag, see below */
#     uint8_t n_sect;        /* section number or NO_SECT */
#     uint16_t n_desc;       /* see <mach-o/stab.h> */
#     uint64_t n_value;      /* value of this symbol (or stab offset) */
# };

class nlist64_t(ctypes.Structure):
    _fields_ = (
        ("n_strx", ctypes.c_uint32),
        ("n_type", ctypes.c_uint8),
        ("n_sect", ctypes.c_uint8),
        ("n_desc", ctypes.c_uint16),
        ("n_value", ctypes.c_uint64),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

    def __str__(self):
        return "\tn_strx = %d" % self.n_strx + "\n\tn_type = %d" % self.n_type + "\n\tn_sect = %d" % self.n_sect + "\n\tn_desc = %d" % self.n_desc + "\n\tn_value = 0x%x" % self.n_value

# struct sysent {        /* system call table */
#     sy_call_t    *sy_call;    /* implementing function */
#     sy_munge_t    *sy_arg_munge32; /* system call arguments munger for 32-bit process */
#     int32_t        sy_return_type; /* system call return types */
#     int16_t        sy_narg;    /* number of args */
#     uint16_t    sy_arg_bytes;    /* Total size of arguments in bytes for
#                      * 32-bit system calls
#                      */
# };

class sysent_t(ctypes.Structure):
    _fields_ = (
        ("sy_call", POINTER64),
        ("sy_arg_munge32", POINTER64),
        ("sy_return_type", ctypes.c_int32),
        ("sy_narg", ctypes.c_int16),
        ("sy_arg_bytes", ctypes.c_uint16),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# struct proc {
#     LIST_ENTRY(proc) p_list;        /* List of all processes. */

#     pid_t        p_pid;            /* Process identifier. (static)*/
#     void *         task;            /* corresponding task (static)*/
#     struct    proc *    p_pptr;             /* Pointer to parent process.(LL) */
#     pid_t        p_ppid;            /* process's parent pid number */
#     pid_t        p_pgrpid;        /* process group id of the process (LL)*/
#     uid_t        p_uid;
#     gid_t        p_gid;
#     uid_t        p_ruid;
#     gid_t        p_rgid;
#     uid_t        p_svuid;
#     gid_t        p_svgid;
#     uint64_t    p_uniqueid;        /* process unique ID - incremented on fork/spawn/vfork, remains same across exec. */
#     uint64_t    p_puniqueid;        /* parent's unique ID - set on fork/spawn/vfork, doesn't change if reparented. */

#     struct lck_mtx_t     p_mlock;        /* mutex lock for proc */

#     char        p_stat;            /* S* process status. (PL)*/
#     char        p_shutdownstate;
#     char        p_kdebug;        /* P_KDEBUG eq (CC)*/
#     char        p_btrace;        /* P_BTRACE eq (CC)*/

#     LIST_ENTRY(proc) p_pglist;        /* List of processes in pgrp.(PGL) */
#     LIST_ENTRY(proc) p_sibling;        /* List of sibling processes. (LL)*/
#     LIST_HEAD(, proc) p_children;        /* Pointer to list of children. (LL)*/
#     TAILQ_HEAD( , uthread) p_uthlist;     /* List of uthreads  (PL) */

#     LIST_ENTRY(proc) p_hash;        /* Hash chain. (LL)*/
#     TAILQ_HEAD( ,eventqelt) p_evlist;    /* (PL) */

#     struct lck_mtx_t    p_fdmlock;        /* proc lock to protect fdesc */
#     struct lck_mtx_t     p_ucred_mlock;        /* mutex lock to protect p_ucred */

#     /* substructures: */
#     kauth_cred_t    p_ucred;        /* Process owner's identity. (PUCL) */
#     struct    filedesc *p_fd;            /* Ptr to open files structure. (PFDL) */
#     struct    pstats *p_stats;        /* Accounting/statistics (PL). */
#     struct    plimit *p_limit;        /* Process limits.(PL) */

#     struct    sigacts *p_sigacts;        /* Signal actions, state (PL) */
#      int        p_siglist;        /* signals captured back from threads */
#     struct lck_spin_t    p_slock;        /* spin lock for itimer/profil protection */

# #define    p_rlimit    p_limit->pl_rlimit

#     struct    plimit *p_olimit;        /* old process limits  - not inherited by child  (PL) */
#     unsigned int    p_flag;            /* P_* flags. (atomic bit ops) */
#     unsigned int    p_lflag;        /* local flags  (PL) */
#     unsigned int    p_listflag;        /* list flags (LL) */
#     unsigned int    p_ladvflag;        /* local adv flags (atomic) */
#     int        p_refcount;        /* number of outstanding users(LL) */
#     int        p_childrencnt;        /* children holding ref on parent (LL) */
#     int        p_parentref;        /* children lookup ref on parent (LL) */

#     pid_t        p_oppid;         /* Save parent pid during ptrace. XXX */
#     u_int        p_xstat;        /* Exit status for wait; also stop signal. */
#     uint8_t p_xhighbits;        /* Stores the top byte of exit status to avoid truncation*/

#     struct    itimerval p_realtimer;        /* Alarm timer. (PSL) */
#     struct    timeval p_rtime;        /* Real time.(PSL)  */
#     struct    itimerval p_vtimer_user;    /* Virtual timers.(PSL)  */
#     struct    itimerval p_vtimer_prof;    /* (PSL) */

#     struct    timeval    p_rlim_cpu;        /* Remaining rlim cpu value.(PSL) */
#     int        p_debugger;        /*  NU 1: can exec set-bit programs if suser */
#     boolean_t    sigwait;    /* indication to suspend (PL) */
#     void    *sigwait_thread;    /* 'thread' holding sigwait(PL)  */
#     void    *exit_thread;        /* Which thread is exiting(PL)  */
#     int    p_vforkcnt;        /* number of outstanding vforks(PL)  */
#         void *  p_vforkact;         /* activation running this vfork proc)(static)  */
#     int    p_fpdrainwait;        /* (PFDL) */
#     pid_t    p_contproc;    /* last PID to send us a SIGCONT (PL) */

#     /* Following fields are info from SIGCHLD (PL) */
#     pid_t    si_pid;            /* (PL) */
#     u_int   si_status;        /* (PL) */
#     u_int    si_code;        /* (PL) */
#     uid_t    si_uid;            /* (PL) */

#     void * vm_shm;            /* (SYSV SHM Lock) for sysV shared memory */

#     user_addr_t            p_dtrace_argv;            /* (write once, read only after that) */
#     user_addr_t            p_dtrace_envp;            /* (write once, read only after that) */
#     lck_mtx_t            p_dtrace_sprlock;        /* sun proc lock emulation */
#     int                p_dtrace_probes;        /* (PL) are there probes for this proc? */
#     u_int                p_dtrace_count;            /* (sprlock) number of DTrace tracepoints */
#         uint8_t                         p_dtrace_stop;                  /* indicates a DTrace-desired stop */
#     struct dtrace_ptss_page*    p_dtrace_ptss_pages;        /* (sprlock) list of user ptss pages */
#     struct dtrace_ptss_page_entry*    p_dtrace_ptss_free_list;    /* (atomic) list of individual ptss entries */
#     struct dtrace_helpers*        p_dtrace_helpers;        /* (dtrace_lock) DTrace per-proc private */
#     struct dof_ioctl_data*        p_dtrace_lazy_dofs;        /* (sprlock) unloaded dof_helper_t's */

# /* XXXXXXXXXXXXX BCOPY'ed on fork XXXXXXXXXXXXXXXX */
# /* The following fields are all copied upon creation in fork. */
# #define    p_startcopy    p_argslen

#     u_int    p_argslen;     /* Length of process arguments. */
#     int      p_argc;            /* saved argc for sysctl_procargs() */
#     user_addr_t user_stack;        /* where user stack was allocated */
#     struct    vnode *p_textvp;    /* Vnode of executable. */
#     off_t    p_textoff;        /* offset in executable vnode */

#     sigset_t p_sigmask;        /* DEPRECATED */
#     sigset_t p_sigignore;    /* Signals being ignored. (PL) */
#     sigset_t p_sigcatch;    /* Signals being caught by user.(PL)  */

#     u_char    p_priority;    /* (NU) Process priority. */
#     u_char    p_resv0;    /* (NU) User-priority based on p_cpu and p_nice. */
#     char    p_nice;        /* Process "nice" value.(PL) */
#     u_char    p_resv1;    /* (NU) User-priority based on p_cpu and p_nice. */

#     // types currently in sys/param.h
#     command_t   p_comm;
#     proc_name_t p_name;    /* can be changed by the process */


#     struct     pgrp *p_pgrp;        /* Pointer to process group. (LL) */
#     uint32_t    p_csflags;    /* flags for codesign (PL) */
#     uint32_t    p_pcaction;    /* action  for process control on starvation */
#     uint8_t p_uuid[16];        /* from LC_UUID load command */

#     /*
#      * CPU type and subtype of binary slice executed in
#      * this process.  Protected by proc lock.
#      */
#     cpu_type_t    p_cputype;
#     cpu_subtype_t    p_cpusubtype;

# /* End area that is copied on creation. */
# /* XXXXXXXXXXXXX End of BCOPY'ed on fork (AIOLOCK)XXXXXXXXXXXXXXXX */
# #define    p_endcopy    p_aio_total_count
#     int        p_aio_total_count;        /* all allocated AIO requests for this proc */
#     int        p_aio_active_count;        /* all unfinished AIO requests for this proc */
#     TAILQ_HEAD( , aio_workq_entry ) p_aio_activeq;     /* active async IO requests */
#     TAILQ_HEAD( , aio_workq_entry ) p_aio_doneq;    /* completed async IO requests */

#     SLIST_HEAD(klist, klist) p_klist;  /* knote list (PL ?)*/

#     struct    rusage_superset *p_ru;    /* Exit information. (PL) */
#     int        p_sigwaitcnt;
#     thread_t     p_signalholder;
#     thread_t     p_transholder;

#     /* DEPRECATE following field  */
#     u_short    p_acflag;    /* Accounting flags. */
#     volatile u_short p_vfs_iopolicy;    /* VFS iopolicy flags. (atomic bit ops) */

#     user_addr_t     p_threadstart;        /* pthread start fn */
#     user_addr_t     p_wqthread;        /* pthread workqueue fn */
#     int     p_pthsize;            /* pthread size */
#     uint32_t    p_pth_tsd_offset;    /* offset from pthread_t to TSD for new threads */
#     user_addr_t    p_stack_addr_hint;    /* stack allocation hint for wq threads */
#     void *     p_wqptr;            /* workq ptr */

#     struct  timeval p_start;            /* starting time */
#     void *    p_rcall;
#     int        p_ractive;
#     int    p_idversion;        /* version of process identity */
#     void *    p_pthhash;            /* pthread waitqueue hash */
#     volatile uint64_t was_throttled __attribute__((aligned(8))); /* Counter for number of throttled I/Os */
#     volatile uint64_t did_throttle __attribute__((aligned(8)));  /* Counter for number of I/Os this proc throttled */

#     uint64_t    p_dispatchqueue_offset;
#     uint64_t    p_dispatchqueue_serialno_offset;
#     uint64_t    p_return_to_kernel_offset;
#     uint64_t    p_mach_thread_self_offset;

#     struct timeval    vm_pressure_last_notify_tstamp;

#     /* Fields protected by proc list lock */
#     TAILQ_ENTRY(proc) p_memstat_list;               /* priority bucket link */
#     uint32_t          p_memstat_state;              /* state */
#     int32_t           p_memstat_effectivepriority;  /* priority after transaction state accounted for */
#     int32_t           p_memstat_requestedpriority;  /* active priority */
#     uint32_t          p_memstat_dirty;              /* dirty state */
#     uint64_t          p_memstat_userdata;           /* user state */
#     uint64_t          p_memstat_idledeadline;       /* time at which process became clean */
#     uint64_t          p_memstat_idle_start;         /* abstime process transitions into the idle band */
#     uint64_t      p_memstat_idle_delta;         /* abstime delta spent in idle band */
#     int32_t           p_memstat_memlimit;           /* cached memory limit, toggles between active and inactive limits */
#     int32_t           p_memstat_memlimit_active;    /* memory limit enforced when process is in active jetsam state */
#     int32_t           p_memstat_memlimit_inactive;    /* memory limit enforced when process is in inactive jetsam state */

#     /* cached proc-specific data required for corpse inspection */
#     pid_t             p_responsible_pid;    /* pid resonsible for this process */
#     _Atomic uint32_t  p_user_faults; /* count the number of user faults generated */

#     struct os_reason     *p_exit_reason;

#     uint64_t    p_user_data;            /* general-purpose storage for userland-provided data */

# };

class timeval_t(ctypes.Structure):
    _fields_ = (
        ("tv_sec", ctypes.c_long),
        ("tv_usec", ctypes.c_int32),
    )

class itimerval_t(ctypes.Structure):
    _fields_ = (
        ("it_interval", timeval_t),
        ("it_value", timeval_t),
    )

class proc_t(ctypes.Structure):
    # struct lck_spin_t {
    #     unsigned long    opaque[10];
    # };
    class lck_spin_t(ctypes.Structure):
        _fields_ = (
            ("opaque", ctypes.c_ulong * 10),
        )
    _fields_ = (
        ("p_list", list_entry),
        ("p_pid", ctypes.c_int32),
        ("task", POINTER64),
        ("p_pptr", POINTER64),
        ("p_ppid", ctypes.c_int32),
        ("p_pgrpid", ctypes.c_int32),
        ("p_uid", ctypes.c_uint32),
        ("p_gid", ctypes.c_uint32),
        ("p_ruid", ctypes.c_uint32),
        ("p_rgid", ctypes.c_uint32),
        ("p_svuid", ctypes.c_uint32),
        ("p_svgid", ctypes.c_uint32),
        ("p_uniqueid", ctypes.c_uint64),
        ("p_puniqueid", ctypes.c_uint64),
        ("p_mlock", lck_mtx_t),
        ("p_stat", ctypes.c_char),
        ("p_shutdownstate", ctypes.c_char),
        ("p_kdebug", ctypes.c_char),
        ("p_btrace", ctypes.c_char),
        ("p_pglist", list_entry),
        ("p_sibling", list_entry),
        ("p_children", list_head),
        ("p_uthlist", tailq_head),
        ("p_hash", list_entry),
        ("p_evlist", tailq_head),
        ("p_fdmlock", lck_mtx_t),
        ("p_ucred_mlock", lck_mtx_t),
        ("p_ucred", POINTER64),
        ("p_fd", POINTER64),
        ("p_stats", POINTER64),
        ("p_limit", POINTER64),
        ("p_sigacts", POINTER64),
        ("p_siglist", ctypes.c_int),
        ("p_slock", lck_spin_t),
        ("p_olimit", POINTER64),
        ("p_flag", ctypes.c_uint),
        ("p_lflag", ctypes.c_uint),
        ("p_listflag", ctypes.c_uint),
        ("p_ladvflag", ctypes.c_uint),
        ("p_refcount", ctypes.c_int),
        ("p_childrencnt", ctypes.c_int),
        ("p_parentref", ctypes.c_int),
        ("p_oppid", ctypes.c_int32),
        ("p_xstat", ctypes.c_uint),
        ("p_xhighbits", ctypes.c_uint8),
        ("p_realtimer", itimerval_t),
        ("p_rtime", timeval_t),
        ("p_vtimer_user", itimerval_t),
        ("p_vtimer_prof", itimerval_t),
        ("p_rlim_cpu", timeval_t),
        ("p_debugger", ctypes.c_int),
        ("sigwait", ctypes.c_int),
        ("sigwait_thread", POINTER64),
        ("exit_thread", POINTER64),
        ("p_vforkcnt", ctypes.c_int),
        ("p_vforkact", POINTER64),
        ("p_fpdrainwait", ctypes.c_int),
        ("p_contproc", ctypes.c_int32),
        ("si_pid", ctypes.c_int32),
        ("si_status", ctypes.c_uint),
        ("si_code", ctypes.c_uint),
        ("si_uid", ctypes.c_uint32),
        ("vm_shm", POINTER64),
        ("p_dtrace_argv", ctypes.c_uint64),
        ("p_dtrace_envp", ctypes.c_uint64),
        ("p_dtrace_sprlock", lck_mtx_t),
        ("p_dtrace_probes", ctypes.c_int),
        ("p_dtrace_count", ctypes.c_uint),
        ("p_dtrace_stop", ctypes.c_uint8),
        ("p_dtrace_ptss_pages", POINTER64),
        ("p_dtrace_ptss_free_list", POINTER64),
        ("p_dtrace_helpers", POINTER64),
        ("p_dtrace_lazy_dofs", POINTER64),
        ("p_argslen", ctypes.c_uint),
        ("p_argc", ctypes.c_int),
        ("user_stack", ctypes.c_uint64),
        ("p_textvp", POINTER64),
        ("p_textoff", ctypes.c_int64),
        ("p_sigmask", ctypes.c_uint32),
        ("p_sigignore", ctypes.c_uint32),
        ("p_sigcatch", ctypes.c_uint32),
        ("p_priority", ctypes.c_ubyte),
        ("p_resv0", ctypes.c_ubyte),
        ("p_nice", ctypes.c_char),
        ("p_resv1", ctypes.c_ubyte),
        ("p_comm", ctypes.c_char * (16 + 1)),
        ("p_name", ctypes.c_char * (2*16 + 1)),
        ("p_pgrp", POINTER64),
        ("p_csflags", ctypes.c_uint32),
        ("p_pcaction", ctypes.c_uint32),
        ("p_uuid", ctypes.c_uint8 * 16),
        ("p_cputype", ctypes.c_int),
        ("p_cpusubtype", ctypes.c_int),
        ("p_aio_total_count", ctypes.c_int),
        ("p_aio_active_count", ctypes.c_int),
        ("p_aio_activeq", tailq_head),
        ("p_aio_doneq", tailq_head),
        ("p_klist", slist_head),
        ("p_ru", POINTER64),
        ("p_sigwaitcnt", ctypes.c_int),
        ("p_signalholder", POINTER64),
        ("p_transholder", POINTER64),
        ("p_acflag", ctypes.c_ushort),
        ("p_vfs_iopolicy", ctypes.c_ushort),
        ("p_threadstart", ctypes.c_uint64),
        ("p_wqthread", ctypes.c_uint64),
        ("p_pthsize", ctypes.c_int),
        ("p_pth_tsd_offset", ctypes.c_uint32),
        ("p_stack_addr_hint", ctypes.c_uint64),
        ("p_wqptr", POINTER64),
        ("p_start", timeval_t),
        ("p_rcall", POINTER64),
        ("p_ractive", ctypes.c_int),
        ("p_idversion", ctypes.c_int),
        ("p_pthhash", POINTER64),
        ("was_throttled", ctypes.c_uint64),
        ("did_throttle", ctypes.c_uint64),
        ("p_dispatchqueue_offset", ctypes.c_uint64),
        ("p_dispatchqueue_serialno_offset", ctypes.c_uint64),
        ("p_return_to_kernel_offset", ctypes.c_uint64),
        ("p_mach_thread_self_offset", ctypes.c_uint64),
        ("vm_pressure_last_notify_tstamp", timeval_t),
        ("p_memstat_list", tailq_entry),
        ("p_memstat_state", ctypes.c_uint32),
        ("p_memstat_effectivepriority", ctypes.c_int32),
        ("p_memstat_requestedpriority", ctypes.c_int32),
        ("p_memstat_dirty", ctypes.c_uint32),
        ("p_memstat_userdata", ctypes.c_uint64),
        ("p_memstat_idledeadline", ctypes.c_uint64),
        ("p_memstat_idle_start", ctypes.c_uint64),
        ("p_memstat_idle_delta", ctypes.c_uint64),
        ("p_memstat_memlimit", ctypes.c_int32),
        ("p_memstat_memlimit_active", ctypes.c_int32),
        ("p_memstat_memlimit_inactive", ctypes.c_int32),
        ("p_responsible_pid", ctypes.c_int32),
        ("p_user_faults", ctypes.c_uint32),
        ("p_exit_reason", POINTER64),
        ("p_user_data", ctypes.c_uint64),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# _STRUCT_TIMESPEC
# {
#     __darwin_time_t tv_sec;
#     long            tv_nsec;
# };
class timespec_t(ctypes.Structure):
    _fields_ = (
        ("tv_sec", ctypes.c_long),
        ("tv_nsec", ctypes.c_long),
    )

# typedef struct __attribute__((packed)) {
#     uint32_t length;

#     /* common attributes */
#     attribute_set_t attrset;
#     attrreference_t name;
#     dev_t st_dev;
#     fsobj_type_t objtype;
#     struct timespec st_birthtimespec;
#     struct timespec st_mtimespec;
#     struct timespec st_ctimespec;
#     struct timespec st_atimespec;
#     uid_t st_uid;
#     gid_t st_gid;
#     uint32_t accessmask;
#     uint32_t st_flags;
#     uint64_t st_ino;

#     /* non-directory attributes */
#     uint32_t st_nlink;
#     off_t allocsize;
#     uint32_t st_blksize;
#     uint32_t st_rdev;
#     off_t st_size;
# } attrListAttributes;

class attrListAttributes_t(ctypes.Structure):
    # typedef struct attribute_set {
    #     attrgroup_t commonattr;         /* common attribute group */
    #     attrgroup_t volattr;            /* Volume attribute group */
    #     attrgroup_t dirattr;            /* directory attribute group */
    #     attrgroup_t fileattr;           /* file attribute group */
    #     attrgroup_t forkattr;           /* fork attribute group */
    # } attribute_set_t;
    class attribute_set_t(ctypes.Structure):
        _fields_ = (
            ("commonattr", ctypes.c_uint32),
            ("volattr", ctypes.c_uint32),
            ("dirattr", ctypes.c_uint32),
            ("fileattr", ctypes.c_uint32),
            ("forkattr", ctypes.c_uint32),
        )

    # typedef struct attrreference {
    #     int32_t     attr_dataoffset;
    #     u_int32_t   attr_length;
    # } attrreference_t;
    class attrreference_t(ctypes.Structure):
        _fields_ = (
            ("attr_dataoffset", ctypes.c_int32),
            ("attr_length", ctypes.c_uint32),
        )

    _fields_ = (
        ("length", ctypes.c_uint32),
        ("attrset", attribute_set_t),
        ("name", attrreference_t),
        ("st_dev", ctypes.c_int32),
        ("objtype", ctypes.c_uint32),
        ("st_birthtimespec", timespec_t),
        ("st_mtimespec", timespec_t),
        ("st_ctimespec", timespec_t),
        ("st_atimespec", timespec_t),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("accessmask", ctypes.c_uint32),
        ("st_flags", ctypes.c_uint32),
        ("st_ino", ctypes.c_uint64),
        ("st_nlink", ctypes.c_uint32),
        ("allocsize", ctypes.c_int64),
        ("st_blksize", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint32),
        ("st_size", ctypes.c_uint32)
    )

# struct attrlist {
#     u_short bitmapcount;            /* number of attr. bit sets in list (should be 5) */
#     u_int16_t reserved;         /* (to maintain 4-byte alignment) */
#     attrgroup_t commonattr;         /* common attribute group */
#     attrgroup_t volattr;            /* Volume attribute group */
#     attrgroup_t dirattr;            /* directory attribute group */
#     attrgroup_t fileattr;           /* file attribute group */
#     attrgroup_t forkattr;           /* fork attribute group */
# };

class attrlist_t(ctypes.Structure):
    _fields_ = (
        ("bitmapcount", ctypes.c_ushort),
        ("reserved", ctypes.c_uint16),
        ("commonattr", ctypes.c_uint32),
        ("volattr", ctypes.c_uint32),
        ("dirattr", ctypes.c_uint32),
        ("fileattr", ctypes.c_uint32),
        ("forkattr", ctypes.c_uint32),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# struct getattrlistbulk_args {
#     char dirfd_l_[PADL_(int)]; int dirfd; char dirfd_r_[PADR_(int)];
#     char alist_l_[PADL_(user_addr_t)]; user_addr_t alist; char alist_r_[PADR_(user_addr_t)];
#     char attributeBuffer_l_[PADL_(user_addr_t)]; user_addr_t attributeBuffer; char attributeBuffer_r_[PADR_(user_addr_t)];
#     char bufferSize_l_[PADL_(user_size_t)]; user_size_t bufferSize; char bufferSize_r_[PADR_(user_size_t)];
#     char options_l_[PADL_(uint64_t)]; uint64_t options; char options_r_[PADR_(uint64_t)];
# };

class getattrlistbulk_args_t(ctypes.Structure):
    _fields_ = (
        ("dirfd", ctypes.c_int),
        ("dirfd_r_", ctypes.c_byte * 4),
        ("alist", ctypes.c_uint64),
        ("attributeBuffer", ctypes.c_uint64),
        ("bufferSize", ctypes.c_uint64),
        ("options", ctypes.c_uint64),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# /* use kern_iovec for system space requests */
# struct kern_iovec {
#     u_int64_t   iov_base;   /* Base address. */
#     u_int64_t   iov_len;    /* Length. */
# };

# /* use user_iovec for user space requests */
# struct user_iovec {
#     user_addr_t iov_base;   /* Base address. */
#     user_size_t iov_len;    /* Length. */
# };

# union iovecs {
#     struct kern_iovec   *kiovp;
#     struct user_iovec   *uiovp;
# };

# /* WARNING - use accessor calls for uio_iov and uio_resid since these */
# /* fields vary depending on the originating address space. */
# struct uio {
#     union iovecs    uio_iovs;       /* current iovec */
#     int             uio_iovcnt;     /* active iovecs */
#     off_t           uio_offset;
#     enum uio_seg    uio_segflg;
#     enum uio_rw     uio_rw;
#     user_size_t uio_resid_64;
#     int             uio_size;       /* size for use with kfree */
#     int             uio_max_iovs;   /* max number of iovecs this uio_t can hold */
#     u_int32_t       uio_flags;      
# };

class kern_iovec_t(ctypes.Structure):
    _fields_ = (
        ("iov_base", ctypes.c_uint64),
        ("iov_len", ctypes.c_uint64),
    )

class user_iovec_t(ctypes.Structure):
    _fields_ = (
        ("iov_base", ctypes.c_uint64),
        ("iov_len", ctypes.c_uint64),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

class iovecs_t(ctypes.Union):
    _fields_ = (
        ("kiovp", POINTER64),
        ("uiovp", POINTER64),
    )

class uio_t(ctypes.Structure):
    _fields_ = (
        ("uio_iovs", iovecs_t),
        ("uio_iovcnt", ctypes.c_int),
        ("uio_offset", ctypes.c_int64),
        ("uio_segflg", ctypes.c_int),
        ("uio_rw", ctypes.c_int),
        ("uio_resid_64", ctypes.c_uint64),
        ("uio_size", ctypes.c_int),
        ("uio_max_iovs", ctypes.c_int),
        ("uio_flags", ctypes.c_uint32),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

# struct vnode_attr {
#     uint64_t    va_supported;
#     uint64_t    va_active;
#     int     va_vaflags;
    
#     dev_t       va_rdev;    /* device id (device nodes only) */
#     uint64_t    va_nlink;   /* number of references to this file */
#     uint64_t    va_total_size;  /* size in bytes of all forks */
#     uint64_t    va_total_alloc; /* disk space used by all forks */
#     uint64_t    va_data_size;   /* size in bytes of the fork managed by current vnode */
#     uint64_t    va_data_alloc;  /* disk space used by the fork managed by current vnode */
#     uint32_t    va_iosize;  /* optimal I/O blocksize */

#     uid_t       va_uid;     /* owner UID */
#     gid_t       va_gid;     /* owner GID */
#     mode_t      va_mode;    /* posix permissions */
#     uint32_t    va_flags;   /* file flags */
#     struct kauth_acl *va_acl;   /* access control list */

#     struct timespec va_create_time; /* time of creation */
#     struct timespec va_access_time; /* time of last access */
#     struct timespec va_modify_time; /* time of last data modification */
#     struct timespec va_change_time; /* time of last metadata change */
#     struct timespec va_backup_time; /* time of last backup */
    
#     uint64_t    va_fileid;  /* file unique ID in filesystem */
#     uint64_t    va_linkid;  /* file link unique ID */
#     uint64_t    va_parentid;    /* parent ID */
#     uint32_t    va_fsid;    /* filesystem ID */
#     uint64_t    va_filerev; /* file revision counter */ /* XXX */
#     uint32_t    va_gen;     /* file generation count */ /* XXX - relationship of
#                                     * these two? */
#     uint32_t    va_encoding;    /* filename encoding script */

#     enum vtype  va_type;    /* file type */
#     char *      va_name;    /* Name for ATTR_CMN_NAME; MAXPATHLEN bytes */
#     guid_t      va_uuuid;   /* file owner UUID */
#     guid_t      va_guuid;   /* file group UUID */
    
#     uint64_t    va_nchildren;     /* Number of items in a directory */
#     uint64_t    va_dirlinkcount;  /* Real references to dir (i.e. excluding "." and ".." refs) */

#     struct kauth_acl *va_base_acl;
#     struct timespec va_addedtime;   /* timestamp when item was added to parent directory */
        
#     uint32_t va_dataprotect_class;  /* class specified for this file if it didn't exist */
#     uint32_t va_dataprotect_flags;  /* flags from NP open(2) to the filesystem */

#     uint32_t va_document_id;

#     uint32_t    va_devid;   /* devid of filesystem */
#     uint32_t    va_objtype; /* type of object */
#     uint32_t    va_objtag;  /* vnode tag of filesystem */
#     uint32_t    va_user_access; /* access for user */
#     uint8_t     va_finderinfo[32];  /* Finder Info */
#     uint64_t    va_rsrc_length; /* Resource Fork length */
#     uint64_t    va_rsrc_alloc;  /* Resource Fork allocation size */
#     fsid_t      va_fsid64;  /* fsid, of the correct type  */

#     uint32_t va_write_gencount;     /* counter that increments each time the file changes */

#     uint64_t va_private_size; /* If the file were deleted, how many bytes would be freed immediately */
# };

class vnode_attr_t(ctypes.Structure):
    # typedef struct {
    # #define KAUTH_GUID_SIZE 16  /* 128-bit identifier */
    #     unsigned char g_guid[KAUTH_GUID_SIZE];
    # } guid_t;
    class guid_t(ctypes.Structure):
        _fields_ = (
            ("g_guid", ctypes.c_ubyte * 16),
        )

    # typedef struct fsid { int32_t val[2]; } fsid_t; /* file system id type */
    class fsid_t(ctypes.Structure):
        _fields_ = (
            ("val", ctypes.c_int32 * 2),
        )

    _fields_ = (
        ("va_supported", ctypes.c_uint64),
        ("va_active", ctypes.c_uint64),
        ("va_vaflags", ctypes.c_int),

        ("va_rdev", ctypes.c_int32),
        ("va_nlink", ctypes.c_uint64),
        ("va_total_size", ctypes.c_uint64),
        ("va_total_alloc", ctypes.c_uint64),
        ("va_data_size", ctypes.c_uint64),
        ("va_data_alloc", ctypes.c_uint64),
        ("va_iosize", ctypes.c_uint32),

        ("va_uid", ctypes.c_uint32),
        ("va_gid", ctypes.c_uint32),
        ("va_mode", ctypes.c_uint16),
        ("va_flags", ctypes.c_uint32),
        ("va_acl", POINTER64),

        ("va_create_time", timespec_t),
        ("va_access_time", timespec_t),
        ("va_modify_time", timespec_t),
        ("va_change_time", timespec_t),
        ("va_backup_time", timespec_t),

        ("va_fileid", ctypes.c_uint64),
        ("va_linkid", ctypes.c_uint64),
        ("va_parentid", ctypes.c_uint64),
        ("va_fsid", ctypes.c_uint32),
        ("va_filerev", ctypes.c_uint64),
        ("va_gen", ctypes.c_uint32),

        ("va_encoding", ctypes.c_uint32),

        ("va_type", ctypes.c_int),
        ("va_name", POINTER64),
        ("va_uuuid", guid_t),
        ("va_guuid", guid_t),

        ("va_nchildren", ctypes.c_uint64),
        ("va_dirlinkcount", ctypes.c_uint64),

        ("va_base_acl", POINTER64),
        ("va_addedtime", timespec_t),

        ("va_dataprotect_class", ctypes.c_uint32),
        ("va_dataprotect_flags", ctypes.c_uint32),
        ("va_document_id", ctypes.c_uint32),

        ("va_devid", ctypes.c_uint32),
        ("va_objtype", ctypes.c_uint32),
        ("va_objtag", ctypes.c_uint32),
        ("va_user_access", ctypes.c_uint32),
        ("va_finderinfo", ctypes.c_uint8 * 32),
        ("va_rsrc_length", ctypes.c_uint64),
        ("va_rsrc_alloc", ctypes.c_uint64),
        ("va_fsid64", fsid_t),

        ("va_write_gencount", ctypes.c_uint32),

        ("va_private_size", ctypes.c_uint64),
    )

    def __init__(self, ql, base):
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj