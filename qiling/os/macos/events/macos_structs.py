#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes, enum

from qiling.os.macos.structs import POINTER64


base_event_normal = 0
class AutoNumberNormalEvent(enum.Enum):
     def __new__(cls):
        value = len(cls.__members__) + base_event_normal
        obj = object.__new__(cls)
        obj._value_ = value
        return obj

class MacOSEventType(AutoNumberNormalEvent):
    EV_SYSCTL = ()
    EV_PROCESS = ()
    EV_NETWORK = ()
    EV_CTL_CONNECT = ()
    EV_CTL_DISCONNECT = ()
    EV_CTL_SEND = ()
    EV_CTL_SETOPT = ()
    EV_CTL_GETOPT = ()
    EV_CTL_RCVD_FUNC = ()
    EV_CTL_SEND_LIST_FUNC = ()
    EV_CTL_BIND_FUNC = ()
    EV_THREAD = ()
    EV_SFLT_UNREGISTERED = ()
    EV_SFLT_ATTACH = ()
    EV_SFLT_DETACH = ()
    EV_SFLT_NOTIFY_CONNECTING = ()
    EV_SFLT_NOTIFY_CONNECTED = ()
    EV_SFLT_NOTIFY_DISCONNECTING = ()
    EV_SFLT_NOTIFY_DISCONNECTED = ()
    EV_SFLT_NOTIFY_FLUSH_READ = ()
    EV_SFLT_NOTIFY_SHUTDOWN = ()
    EV_SFLT_NOTIFY_CANTRECVMORE = ()
    EV_SFLT_NOTIFY_CANTSENDMORE = ()
    EV_SFLT_NOTIFY_CLOSING = ()
    EV_SFLT_NOTIFY_BOUND = ()
    EV_SFLT_GETPEERNAME = ()
    EV_SFLT_GETSOCKNAME = ()
    EV_SFLT_DATA_IN = ()
    EV_SFLT_DATA_OUT = ()
    EV_SFLT_CONNECT_IN = ()
    EV_SFLT_CONNECT_OUT = ()
    EV_SFLT_BIND = ()
    EV_SFLT_SETOPTION = ()
    EV_SFLT_GETOPTION = ()
    EV_SFLT_LISTEN = ()
    EV_SFLT_IOCTL = ()
    EV_KAUTH_GENERIC = ()
    EV_KAUTH_PROCESS = ()
    EV_KAUTH_VNODE = ()
    EV_KAUTH_FILEOP = ()
    EV_IPF_INPUT = ()
    EV_IPF_OUTPUT = ()
    EV_IPF_DETACH = ()

# enum {
# 	sock_evt_connecting             = 1,
# 	sock_evt_connected              = 2,
# 	sock_evt_disconnecting          = 3,
# 	sock_evt_disconnected           = 4,
# 	sock_evt_flush_read             = 5,
# 	sock_evt_shutdown               = 6, /* param points to an integer specifying how (read, write, or both) see man 2 shutdown */
# 	sock_evt_cantrecvmore           = 7,
# 	sock_evt_cantsendmore           = 8,
# 	sock_evt_closing                = 9,
# 	sock_evt_bound                  = 10
# };

base_event_socket = 0x1000

class SocketEvent(enum.Enum):
    CONNECTING = 0x1001
    CONNECTED = 0x1002
    DISCONNECTING = 0x1003
    DISCONNECTED = 0x1004
    FLUSH_READ = 0x1005
    SHUTDOWN = 0x1006
    CANTRECVMORE = 0x1007
    CANTSENDMORE = 0x1008
    CLOSING = 0x1009
    BOUND = 0x100a
    
class NetworkProtocol(enum.Enum):
    IPPROTO_IP              = 0
    IPPROTO_ICMP            = 1
    IPPROTO_IGMP            = 2
    IPPROTO_GGP             = 3
    IPPROTO_IPV4            = 4
    IPPROTO_TCP             = 6
    IPPROTO_ST              = 7
    IPPROTO_EGP             = 8
    IPPROTO_PIGP            = 9
    IPPROTO_RCCMON          = 10
    IPPROTO_NVPII           = 11
    IPPROTO_PUP             = 12
    IPPROTO_ARGUS           = 13
    IPPROTO_EMCON           = 14
    IPPROTO_XNET            = 15
    IPPROTO_CHAOS           = 16
    IPPROTO_UDP             = 17
    IPPROTO_MUX             = 18
    IPPROTO_MEAS            = 19
    IPPROTO_HMP             = 20
    IPPROTO_PRM             = 21
    IPPROTO_IDP             = 22
    IPPROTO_TRUNK1          = 23
    IPPROTO_TRUNK2          = 24
    IPPROTO_LEAF1           = 25
    IPPROTO_LEAF2           = 26
    IPPROTO_RDP             = 27
    IPPROTO_IRTP            = 28
    IPPROTO_TP              = 29
    IPPROTO_BLT             = 30
    IPPROTO_NSP             = 31
    IPPROTO_INP             = 32
    IPPROTO_SEP             = 33
    IPPROTO_3PC             = 34
    IPPROTO_IDPR            = 35
    IPPROTO_XTP             = 36
    IPPROTO_DDP             = 37
    IPPROTO_CMTP            = 38
    IPPROTO_TPXX            = 39
    IPPROTO_IL              = 40
    IPPROTO_IPV6            = 41
    IPPROTO_SDRP            = 42
    IPPROTO_ROUTING 	    = 43
    IPPROTO_FRAGMENT        = 44
    IPPROTO_IDRP            = 45
    IPPROTO_RSVP            = 46
    IPPROTO_GRE             = 47
    IPPROTO_MHRP            = 48
    IPPROTO_BHA             = 49
    IPPROTO_ESP             = 50
    IPPROTO_AH              = 51
    IPPROTO_INLSP           = 52
    IPPROTO_SWIPE           = 53
    IPPROTO_NHRP            = 54
    IPPROTO_ICMPV6          = 58
    IPPROTO_NONE            = 59
    IPPROTO_DSTOPTS         = 60
    IPPROTO_AHIP            = 61
    IPPROTO_CFTP            = 62
    IPPROTO_HELLO           = 63
    IPPROTO_SATEXPAK        = 64
    IPPROTO_KRYPTOLAN       = 65
    IPPROTO_RVD             = 66
    IPPROTO_IPPC            = 67
    IPPROTO_ADFS            = 68
    IPPROTO_SATMON          = 69
    IPPROTO_VISA            = 70
    IPPROTO_IPCV            = 71
    IPPROTO_CPNX            = 72
    IPPROTO_CPHB            = 73
    IPPROTO_WSN             = 74
    IPPROTO_PVP             = 75
    IPPROTO_BRSATMON        = 76
    IPPROTO_ND              = 77
    IPPROTO_WBMON           = 78
    IPPROTO_WBEXPAK         = 79
    IPPROTO_EON             = 80
    IPPROTO_VMTP            = 81
    IPPROTO_SVMTP           = 82
    IPPROTO_VINES           = 83
    IPPROTO_TTP             = 84
    IPPROTO_IGP             = 85
    IPPROTO_DGP             = 86
    IPPROTO_TCF             = 87
    IPPROTO_IGRP            = 88
    IPPROTO_OSPFIGP         = 89
    IPPROTO_SRPC            = 90
    IPPROTO_LARP            = 91
    IPPROTO_MTP             = 92
    IPPROTO_AX25            = 93
    IPPROTO_IPEIP           = 94
    IPPROTO_MICP            = 95
    IPPROTO_SCCSP           = 96
    IPPROTO_ETHERIP         = 97
    IPPROTO_ENCAP           = 98
    IPPROTO_APES            = 99
    IPPROTO_GMTP            = 100
    IPPROTO_PIM             = 103
    IPPROTO_IPCOMP          = 108
    IPPROTO_PGM             = 113
    IPPROTO_SCTP            = 132
    IPPROTO_DIVERT          = 254
    IPPROTO_RAW             = 255
    IPPROTO_MAX             = 256
    IPPROTO_DONE            = 257

# KAUTH_FILEOP_OPEN                       1
# KAUTH_FILEOP_CLOSE                      2
# KAUTH_FILEOP_RENAME                     3
# KAUTH_FILEOP_EXCHANGE                   4
# KAUTH_FILEOP_LINK                       5
# KAUTH_FILEOP_EXEC                       6
# KAUTH_FILEOP_DELETE                     7
# KAUTH_FILEOP_WILL_RENAME                8
class Kauth(enum.Enum):
    KAUTH_FILEOP_OPEN = 1
    KAUTH_FILEOP_CLOSE = 2
    KAUTH_FILEOP_RENAME = 3
    KAUTH_FILEOP_EXCHANGE = 4
    KAUTH_FILEOP_LINK = 5
    KAUTH_FILEOP_EXEC = 6
    KAUTH_FILEOP_DELETE = 7
    KAUTH_FILEOP_WILL_RENAME = 8

# struct sysctl_oid {
# 	struct sysctl_oid_list *oid_parent;
# 	SLIST_ENTRY(sysctl_oid) oid_link;
# 	int		oid_number;
# 	int		oid_kind;
# 	void		*oid_arg1;
# 	int		oid_arg2;
# 	const char	*oid_name;
# 	int 		(*oid_handler) SYSCTL_HANDLER_ARGS;
# 	const char	*oid_fmt;
# 	const char	*oid_descr; /* offsetof() field / long description */
# 	int		oid_version;
# 	int		oid_refcnt;
# };

class sysctl_oid_t(ctypes.Structure):
    class slist_entry(ctypes.Structure):
        _fields_ = (
            ("sle_next", POINTER64),
        )
    _fields_ = (
        ("oid_parent", POINTER64),
        ("oid_link", slist_entry),
        ("oid_number", ctypes.c_int32),
        ("oid_kind", ctypes.c_int32),
        ("oid_arg1", POINTER64),
        ("oid_arg2", ctypes.c_int32),
        ("oid_name", POINTER64),
        ("oid_handler", POINTER64),
        ("oid_fmt", POINTER64),
        ("oid_descr", POINTER64),
        ("oid_version", ctypes.c_int32),
        ("oid_refcnt", ctypes.c_int32),
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
            if isinstance(getattr(self, field[0]), POINTER64):
                self.ql.log.info("%s: 0x%x" % (field[0], getattr(self, field[0]).value))
            elif isinstance(getattr(self, field[0]), sysctl_oid_t.slist_entry):
                self.ql.log.info("%s: Struct( 0x%x )" % (field[0], getattr(self, field[0]).sle_next.value))
            else:
                self.ql.log.info("%s: 0x%x" % (field[0], getattr(self, field[0])))

class sysctl_args_t(ctypes.Structure):
    _fields_ = (
        ("name", ctypes.c_int32 * 2),
	("namelen", ctypes.c_uint32),
	("old", POINTER64),
	("oldlenp", POINTER64),
	("new", POINTER64),
	("newlen", ctypes.c_uint64),
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

# struct sysctlbyname_args {
#     const char * 	name
#     size_t 	namelen
#     void * 	old
#     size_t * 	oldlenp
#     void * 	new
#     size_t 	newlen
#  }

class sysctlbyname_args_t(ctypes.Structure):
    _fields_ = (
        ("name", POINTER64),
        ("namelen", ctypes.c_size_t),
        ("old", POINTER64),
        ("oldlenp", POINTER64),
        ("new", POINTER64),
        ("newlen", ctypes.c_size_t),
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

# struct sysctl_req {
# 	struct proc	*p;
# 	int		lock;
# 	user_addr_t	oldptr;		/* pointer to user supplied buffer */
# 	size_t		oldlen;		/* user buffer length (also returned) */
# 	size_t		oldidx;		/* total data iteratively copied out */
# 	int		(*oldfunc)(struct sysctl_req *, const void *, size_t);
# 	user_addr_t	newptr;		/* buffer containing new value */
# 	size_t		newlen;		/* length of new value */
# 	size_t		newidx;		/* total data iteratively copied in */
# 	int		(*newfunc)(struct sysctl_req *, void *, size_t);
# };

class sysctl_req_t(ctypes.Structure):
    _fields_ = (
        ("p", POINTER64),
        ("lock", ctypes.c_int32),
        ("oldptr", POINTER64),
        ("oldlen", ctypes.c_size_t),
        ("oldidx", ctypes.c_size_t),
        ("oldfunc", POINTER64),
        ("newptr", POINTER64),
        ("newlen", ctypes.c_size_t),
        ("newidx", ctypes.c_size_t),
        ("newfunc", ctypes.c_int32),
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

# struct kern_ctl_reg
# {
# 	/* control information */
# 	char		ctl_name[MAX_KCTL_NAME];
# 	u_int32_t	ctl_id;
# 	u_int32_t	ctl_unit;
# 
#     /* control settings */
#     u_int32_t	ctl_flags;
#     u_int32_t	ctl_sendsize;
#     u_int32_t	ctl_recvsize;
# 
#     /* Dispatch functions */
#     ctl_connect_func	ctl_connect;
#     ctl_disconnect_func	ctl_disconnect;
#     ctl_send_func		ctl_send;
#     ctl_setopt_func		ctl_setopt;
#     ctl_getopt_func		ctl_getopt;
# #ifdef KERNEL_PRIVATE
#     ctl_rcvd_func		ctl_rcvd;	/* Only valid if CTL_FLAG_REG_EXTENDED is set */
#     ctl_send_list_func		ctl_send_list;	/* Only valid if CTL_FLAG_REG_EXTENDED is set */
# 	ctl_bind_func		ctl_bind;
# #endif /* KERNEL_PRIVATE */
# };

class kern_ctl_reg_t(ctypes.Structure):
    _fields_ = (
        ("ctl_name", ctypes.c_char * 96),
        ("ctl_id", ctypes.c_uint32),
        ("ctl_unit", ctypes.c_uint32),
        ("ctl_flags", ctypes.c_uint32),
        ("ctl_sendsize", ctypes.c_uint32),
        ("ctl_recvsize", ctypes.c_uint32),
        ("ctl_connect", POINTER64),
        ("ctl_disconnect", POINTER64),
        ("ctl_send", POINTER64),
        ("ctl_setopt", POINTER64),
        ("ctl_getopt", POINTER64),
        ("ctl_rcvd", POINTER64),
        ("ctl_send_list", POINTER64),
        ("ctl_bind", POINTER64),
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
            if isinstance(getattr(self, field[0]), POINTER64):
                self.ql.log.info("%s: 0x%x" % (field[0], getattr(self, field[0]).value))
            elif isinstance(getattr(self, field[0]), int):
                self.ql.log.info("%s: %d" % (field[0], getattr(self, field[0])))
            elif isinstance(getattr(self, field[0]), bytes):
                self.ql.log.info("%s: %s" % (field[0], getattr(self, field[0]).decode()))


# struct sockaddr_ctl {
#     u_char	sc_len;		/* depends on size of bundle ID string */
#     u_char	sc_family;	/* AF_SYSTEM */
#     u_int16_t 	ss_sysaddr;	/* AF_SYS_KERNCONTROL */
#     u_int32_t	sc_id; 		/* Controller unique identifier  */
#     u_int32_t 	sc_unit;	/* Developer private unit number */
#     u_int32_t 	sc_reserved[5];
# };

class sockaddr_ctl_t(ctypes.Structure):
    _fields_ = (
        ("sc_len", ctypes.c_ubyte),
        ("sc_family", ctypes.c_ubyte),
        ("ss_sysaddr", ctypes.c_uint16),
        ("sc_id", ctypes.c_uint32),
        ("sc_unit", ctypes.c_uint32),
        ("sc_reserved", ctypes.c_uint32 * 5),
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

# struct m_hdr {
# 	struct mbuf	*mh_next;	/* next buffer in chain */
# 	struct mbuf	*mh_nextpkt;	/* next chain in queue/record */
# 	caddr_t		mh_data;	/* location of data */
# 	int32_t		mh_len;		/* amount of data in this mbuf */
# 	u_int16_t	mh_type;	/* type of data in this mbuf */
# 	u_int16_t	mh_flags;	/* flags; see below */
# }

class m_hdr_t(ctypes.Structure):
    _fields_ = (
        ("mh_next", POINTER64),
        ("mh_nextpkt", POINTER64),
        ("mh_data", POINTER64),
        ("mh_len", ctypes.c_int32),
        ("mh_type", ctypes.c_uint16),
        ("mh_flags", ctypes.c_uint16),
    )

class tag_t(ctypes.Structure):
    _fields_ = (
        ("packet_tags", POINTER64),
    )

# struct tcp_pktinfo {
#     union {
#         struct {
#                 u_int32_t segsz;	/* segment size (actual MSS) */
#                 u_int32_t start_seq;	/* start seq of this packet */
#         } __tx;
#         struct {
#                 u_int16_t lro_pktlen;	/* max seg size encountered */
#                 u_int8_t  lro_npkts;	/* # of coalesced TCP pkts */
#                 u_int8_t  lro_timediff;	/* time spent in LRO */
#         } __rx;
#     } __offload;
#     union {
#         u_int32_t	pri;		/* send msg priority */
#         u_int32_t	seq;		/* recv msg sequence # */
#     } __msgattr;
# };
class tcp_pktinfo_t(ctypes.Structure):
    class __offload_u(ctypes.Union):
        class __tx_t(ctypes.Structure):
            _fields_ = (
                ("segsz", ctypes.c_uint32),
                ("start_seq", ctypes.c_uint32),
            )
        class __rx_t(ctypes.Structure):
            _fields_ = (
                ("lro_pktlen", ctypes.c_uint16),
                ("lro_npkts", ctypes.c_uint8),
                ("lro_timediff", ctypes.c_uint8),
            )
        _fields_ = (
            ("__tx", __tx_t),
            ("__rx", __rx_t),
        )
    class __msgattr_u(ctypes.Union):
        _fields_ = (
            ("pri", ctypes.c_uint32),
            ("seq", ctypes.c_uint32),
        )
    _fields_ = (
        ("__offload", __offload_u),
        ("__msgattr", __msgattr_u),
    )

# struct mptcp_pktinfo {
#     u_int64_t	mtpi_dsn;	/* MPTCP Data Sequence Number */
#     u_int32_t	mtpi_rel_seq;	/* Relative Seq Number */
#     u_int16_t	mtpi_length;	/* Length of mapping */
#     u_int16_t	mtpi_csum;
# };
class mptcp_pktinfo_t(ctypes.Structure):
    _fields_ = (
        ("mtpi_dsn", ctypes.c_uint64),
        ("mtpi_rel_seq", ctypes.c_uint32),
        ("mtpi_length", ctypes.c_uint16),
        ("mtpi_csum", ctypes.c_uint16),
    )

# struct tcp_mtag {
#     union {
#         struct tcp_pktinfo	tm_tcp;		/* TCP and below */
#         struct mptcp_pktinfo	tm_mptcp;	/* MPTCP-TCP only */
#     };
# };
class tcp_mtag_t(ctypes.Structure):
    class pktinfo_u(ctypes.Union):
        _fields_ = (
            ("tm_tcp", tcp_pktinfo_t),
            ("tm_mptcp", mptcp_pktinfo_t),
        )
    _anonymous_ = ("tmp_union",)
    _fields_ = (
        ("tmp_union", pktinfo_u),
    )

# struct proto_mtag_ {
#     union {
#         struct tcp_mtag	tcp;		/* TCP specific */
#     } __pr_u;
# };
class proto_mtag__t(ctypes.Structure):
    class __pr_u_u(ctypes.Union):
        _fields_ = (
            ("tcp", tcp_mtag_t),
        )
    _fields_ = (
        ("__pr_u", __pr_u_u),
    )

# struct pf_mtag {
#     u_int16_t	pftag_flags;	/* PF_TAG flags */
#     u_int16_t	pftag_rtableid;	/* alternate routing table id */
#     u_int16_t	pftag_tag;
#     u_int16_t	pftag_routed;
# #if PF_ECN
#     void		*pftag_hdr;	/* saved hdr pos in mbuf, for ECN */
# #endif /* PF_ECN */
# };
class pf_mtag_t(ctypes.Structure):
    _fields_ = (
        ("pftag_flags", ctypes.c_int16),
        ("pftag_rtableid", ctypes.c_int16),
        ("pftag_tag", ctypes.c_int16),
        ("pftag_routed", ctypes.c_int16),
    )

# struct necp_mtag_ {
#     u_int32_t	necp_policy_id;
#     u_int32_t	necp_last_interface_index;
#     u_int32_t	necp_route_rule_id;
#     u_int32_t	necp_app_id;
# };
class necp_mtag__t(ctypes.Structure):
    _fields_ = (
        ("necp_policy_id", ctypes.c_int32),
        ("necp_last_interface_index", ctypes.c_int32),
        ("necp_route_rule_id", ctypes.c_int32),
        ("necp_app_id", ctypes.c_int32),
    )



# struct {
#     union {
#         u_int8_t	__mpriv8[16];
#         u_int16_t	__mpriv16[8];
#         struct {
#             union {
#                 u_int8_t	__val8[4];
#                 u_int16_t	__val16[2];
#                 u_int32_t	__val32;
#             } __mpriv32_u;
#         } __mpriv32[4];
#         u_int64_t	__mpriv64[2];
#     } __mpriv_u;
# } pkt_mpriv __attribute__((aligned(4)));
class pkt_mpriv_t(ctypes.Structure):
    class __mpriv_u_u(ctypes.Union):
        class __mpriv32_t(ctypes.Structure):
            class __mpriv32_u_u(ctypes.Union):
                _fields_ = (
                    ("__val8", ctypes.c_int8 * 4),
                    ("__val16", ctypes.c_int16 * 2),
                    ("__val32", ctypes.c_int32),
                )
            _fields_ = (
                ("__mpriv32_u", __mpriv32_u_u),
            )
        _fields_ = (
            ("__mpriv32", __mpriv32_t * 4),
            ("__mpriv64", ctypes.c_uint64 * 2),
        )
    _fields_ = (
        ("__mpriv_u", __mpriv_u_u),
    )

# struct pkthdr {
# 	struct ifnet *rcvif;		/* rcv interface */
# 	void	*pkt_hdr;		/* pointer to packet header */
# 	int32_t	len;			/* total packet length */
# 	u_int32_t csum_flags;		/* flags regarding checksum */
# 	union {
# 		struct {
# 			u_int16_t val;	 /* checksum value */
# 			u_int16_t start; /* checksum start offset */
# 		} _csum_rx;
# 		struct {
# 			u_int16_t start; /* checksum start offset */
# 			u_int16_t stuff; /* checksum stuff offset */
# 		} _csum_tx;
# 		u_int32_t csum_data;	/* data field used by csum routines */
# 	};
# 	u_int16_t vlan_tag;		/* VLAN tag, host byte order */
# 	u_int8_t pkt_proto;		/* IPPROTO value */
# 	u_int8_t pkt_flowsrc;		/* FLOWSRC values */
# 	u_int32_t pkt_flowid;		/* flow ID */
# 	u_int32_t pkt_flags;		/* PKTF flags (see below) */
# 	u_int32_t pkt_svc;		/* MBUF_SVC value */
# 
# 	u_int32_t pkt_compl_context;		/* Packet completion context */
# 
# 	union {
# 		struct {
# 			u_int16_t src;		/* ifindex of src addr i/f */
# 			u_int16_t src_flags;	/* src PKT_IFAIFF flags */
# 			u_int16_t dst;		/* ifindex of dst addr i/f */
# 			u_int16_t dst_flags;	/* dst PKT_IFAIFF flags */
# 		} _pkt_iaif;
# 		u_int64_t pkt_ifainfo;	/* data field used by ifainfo */
# 		struct {
# 			u_int32_t if_data; /* bytes in interface queue */
# 			u_int32_t sndbuf_data; /* bytes in socket buffer */
# 		} _pkt_bsr;	/* Buffer status report used by cellular interface */
# 	};
# 	u_int64_t pkt_timestamp;	/* enqueue time */
# 
# 	SLIST_HEAD(packet_tags, m_tag) tags; /* list of external tags */
# 	union builtin_mtag builtin_mtag;
# 	struct {
# 		union {
# 			u_int8_t	__mpriv8[16];
# 			u_int16_t	__mpriv16[8];
# 			struct {
# 				union {
# 					u_int8_t	__val8[4];
# 					u_int16_t	__val16[2];
# 					u_int32_t	__val32;
# 				} __mpriv32_u;
# 			}		__mpriv32[4];
# 			u_int64_t	__mpriv64[2];
# 		} __mpriv_u;
# 	} pkt_mpriv __attribute__((aligned(4)));
# 	u_int32_t redzone;		/* red zone */
# 	u_int32_t pkt_compl_callbacks;	/* Packet completion callbacks */
# };

class pkthdr_t(ctypes.Structure):
    class chksum_union(ctypes.Union):
        class _csum_rx_t(ctypes.Structure):
            _fields_ = (
                ("val", ctypes.c_uint16),
                ("start", ctypes.c_uint16),
            )
        class _csum_tx_t(ctypes.Structure):
            _fields_ = (
                ("start", ctypes.c_uint16),
                ("stuff", ctypes.c_uint16),
            )
        _fields_ = [
            ("_csum_rx", _csum_rx_t),
            ("_csum_tx", _csum_tx_t),
            ("csum_data", ctypes.c_uint32),
        ]

    class interface_union(ctypes.Union):
        class _pkt_iaif_t(ctypes.Structure):
            _fields_ = (
                ("src", ctypes.c_uint16),
                ("src_flags", ctypes.c_uint16),
                ("dst", ctypes.c_uint16),
                ("dst_flags", ctypes.c_uint16),
            )
        class _pkt_bsr_t(ctypes.Structure):
            _fields_ = (
                ("if_data", ctypes.c_uint32),
                ("sndbuf_data", ctypes.c_uint32),
            )
        _fields_ = (
            ("_pkt_iaif", _pkt_iaif_t),
            ("pkt_ifainfo", ctypes.c_uint64),
            ("_pkt_bsr", _pkt_bsr_t),
        )

#     union builtin_mtag {
# 	struct {
# 		struct proto_mtag_ _proto_mtag;	/* built-in protocol-specific tag */
# 		struct pf_mtag	_pf_mtag;	/* built-in PF tag */
# 		struct necp_mtag_ _necp_mtag; /* built-in NECP tag */
# 	} _net_mtag;
# 	struct driver_mtag_ _drv_mtag;
#     }
    class builtin_mtag_u(ctypes.Union):
#         struct driver_mtag_ {
#             uintptr_t		_drv_tx_compl_arg;
#             uintptr_t		_drv_tx_compl_data;
#             kern_return_t		_drv_tx_status;
#             uint16_t		_drv_flowid;
#         };
        class driver_mtag__t(ctypes.Structure):
            _fields_ = (
                ("_drv_tx_compl_arg", POINTER64),
                ("_drv_tx_compl_data", POINTER64),
                ("_drv_tx_status", ctypes.c_int32),
                ("_drv_flowid", ctypes.c_int16),
            )
        class _net_mtag_t(ctypes.Structure):
            _fields_ = (
                ("_proto_mtag", proto_mtag__t),
                ("_pf_mtag", pf_mtag_t),
                ("_necp_mtag", necp_mtag__t),
            )
        _fields_ = (
            ("_net_mtag", _net_mtag_t),
            ("_drv_mtag", driver_mtag__t),
        )

    _anonymous_ = ("tmp_chksum_union", "tmp_interface_union", )
    _fields_ = (
        ("rcvif", POINTER64),
        ("pkt_hdr", POINTER64),
        ("len", ctypes.c_int32),
        ("csum_flags", ctypes.c_uint32),
        ("tmp_chksum_union", chksum_union),
        ("vlan_tag", ctypes.c_uint16),
        ("pkt_proto", ctypes.c_uint8),
        ("pkt_flowsrc", ctypes.c_uint8),
        ("pkt_flowid", ctypes.c_uint32),
        ("pkt_flags", ctypes.c_uint32),
        ("pkt_svc", ctypes.c_uint32),
        ("pkt_compl_context", ctypes.c_uint32),
        ("tmp_interface_union", interface_union),
        ("pkt_timestamp", ctypes.c_uint64),
        ("tags", tag_t),
        ("builtin_mtag", builtin_mtag_u),
        ("pkt_mpriv", pkt_mpriv_t),
        ("redzone", ctypes.c_uint32),
        ("pkt_compl_callbacks", ctypes.c_uint32),
    )

# struct m_ext {
# 	caddr_t	ext_buf;		/* start of buffer */
# 	m_ext_free_func_t ext_free;	/* free routine if not the usual */
# 	u_int	ext_size;		/* size of buffer, for ext_free */
# 	caddr_t	ext_arg;		/* additional ext_free argument */
# 	struct ext_ref {
# 		struct mbuf *paired;
# 		u_int16_t minref;
# 		u_int16_t refcnt;
# 		u_int16_t prefcnt;
# 		u_int16_t flags;
# 		u_int32_t priv;
# 		uintptr_t ext_token;
# 	} *ext_refflags;
# };
class ext_ref(ctypes.Structure):
    _fields_ = (
        ("paired", POINTER64),
        ("minref", ctypes.c_uint16),
        ("refcnt", ctypes.c_uint16),
        ("prefcnt", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("priv", ctypes.c_uint32),
        ("ext_token", POINTER64),
    )
class m_ext_t(ctypes.Structure):
    _fields_ = (
        ("ext_buf", POINTER64),
        ("ext_free", POINTER64),
        ("ext_size", ctypes.c_uint32),
        ("ext_arg", POINTER64),
        ("ext_refflags", POINTER64),
    )

# struct mbuf {
# 	struct m_hdr m_hdr;
# 	union {
# 		struct {
# 			struct pkthdr MH_pkthdr;	/* M_PKTHDR set */
# 			union {
# 				struct m_ext MH_ext;	/* M_EXT set */
# 				char	MH_databuf[_MHLEN];
# 			} MH_dat;
# 		} MH;
# 		char	M_databuf[_MLEN];		/* !M_PKTHDR, !M_EXT */
# 	} M_dat;
# };

#define	MSIZESHIFT	8			/* 256 */
#define	MSIZE		(1 << MSIZESHIFT)	/* size of an mbuf */
#define	_MLEN		(MSIZE - sizeof(struct m_hdr))	/* normal data len */
#define	_MHLEN		(_MLEN - sizeof(struct pkthdr))	/* data len w/pkthdr */

MSIZESHIFT = 8
MSIZE = (1 << MSIZESHIFT)
_MLEN = (MSIZE - ctypes.sizeof(m_hdr_t))
_MHLEN = (_MLEN - ctypes.sizeof(pkthdr_t))

class mbuf_t(ctypes.Structure):
    class M_dat_u(ctypes.Union):
        class MH_t(ctypes.Structure):
            class MH_dat_u(ctypes.Union):
                _fields_ = (
                    ("MH_ext", m_ext_t),
                    ("MH_databuf", ctypes.c_char * _MHLEN)
                )
            _fields_ = (
                ("MH_pkthdr", pkthdr_t),
                ("MH_dat", MH_dat_u),
            )
        _fields_ = (
            ("MH", MH_t),
            ("M_databuf", ctypes.c_char * _MLEN),
        )
    _fields_ = (
        ("m_hdr", m_hdr_t),
        ("M_dat", M_dat_u),
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

# enum sopt_dir { SOPT_GET, SOPT_SET };
# struct sockopt {
# 	enum sopt_dir sopt_dir; /* is this a get or a set? */
# 	int	sopt_level;	/* second arg of [gs]etsockopt */
# 	int	sopt_name;	/* third arg of [gs]etsockopt */
# 	void* sopt_val;	/* fourth arg of [gs]etsockopt */
# 	size_t	sopt_valsize;	/* (almost) fifth arg of [gs]etsockopt */
# 	void *sopt_p;	/* calling process or null if kernel */
# };

class sockopt_t(ctypes.Structure):
    _fields_ = (
        ("sopt_dir", ctypes.c_uint64),
        ("sopt_level", ctypes.c_int32),
        ("sopt_name", ctypes.c_int32),
        ("sopt_val", POINTER64),
        ("sopt_valsize", ctypes.c_uint64),
        ("sopt_p", ctypes.c_uint64),
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

# struct sflt_filter {
# 	sflt_handle                     sf_handle;
# 	int                             sf_flags;
# 	char                            *sf_name;
# 
# 	sf_unregistered_func            sf_unregistered;
# 	sf_attach_func                  sf_attach;
# 	sf_detach_func                  sf_detach;
# 
# 	sf_notify_func                  sf_notify;
# 	sf_getpeername_func             sf_getpeername;
# 	sf_getsockname_func             sf_getsockname;
# 	sf_data_in_func                 sf_data_in;
# 	sf_data_out_func                sf_data_out;
# 	sf_connect_in_func              sf_connect_in;
# 	sf_connect_out_func             sf_connect_out;
# 	sf_bind_func                    sf_bind;
# 	sf_setoption_func               sf_setoption;
# 	sf_getoption_func               sf_getoption;
# 	sf_listen_func                  sf_listen;
# 	sf_ioctl_func                   sf_ioctl;
# 	/*
# 	 * The following are valid only if SFLT_EXTENDED flag is set.
# 	 * Initialize sf_ext_len to sizeof sflt_filter_ext structure.
# 	 * Filters must also initialize reserved fields with zeroes.
# 	 */
# 	struct sflt_filter_ext {
# 		unsigned int            sf_ext_len;
# 		sf_accept_func          sf_ext_accept;
# 		void                    *sf_ext_rsvd[5];        /* Reserved */
# 	} sf_ext;
# };

class sflt_filter_t(ctypes.Structure):
    class sflt_filter_ext(ctypes.Structure):
        _fields_ = (
            ("sf_ext_len", ctypes.c_uint32),
            ("sf_ext_accept", POINTER64),
            ("sf_ext_rsvd", POINTER64 * 5),
        )

    _fields_ = (
        ("sf_handle", ctypes.c_uint32),
        ("sf_flags", ctypes.c_int32),
        ("sf_name", POINTER64),
        ("sf_unregistered", POINTER64),
        ("sf_attach", POINTER64),
        ("sf_detach", POINTER64),
        ("sf_notify", POINTER64),
        ("sf_getpeername", POINTER64),
        ("sf_getsockname", POINTER64),
        ("sf_data_in", POINTER64),
        ("sf_data_out", POINTER64),
        ("sf_connect_in", POINTER64),
        ("sf_connect_out", POINTER64),
        ("sf_bind", POINTER64),
        ("sf_setoption", POINTER64),
        ("sf_getoption", POINTER64),
        ("sf_listen", POINTER64),
        ("sf_ioctl", POINTER64),
        ("sf_ext", sflt_filter_ext),
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
        self.ql.log.info("[*] Dumping object: %s" % (self.sf_name))
        for field in self._fields_:
            if isinstance(getattr(self, field[0]), POINTER64):
                self.ql.log.info("%s: 0x%x" % (field[0], getattr(self, field[0]).value))
            elif isinstance(getattr(self, field[0]), int):
                self.ql.log.info("%s: %d" % (field[0], getattr(self, field[0])))
            elif isinstance(getattr(self, field[0]), bytes):
                self.ql.log.info("%s: %s" % (field[0], getattr(self, field[0]).decode()))

# struct sockaddr_in {
# 	__uint8_t	sin_len;
# 	sa_family_t	sin_family;
# 	in_port_t	sin_port;
# 	struct	in_addr sin_addr;
# 	char		sin_zero[8];
# };

class sockaddr_in_t(ctypes.Structure):
#     struct in_addr {
# 	in_addr_t s_addr;
#     };
    class in_addr_t(ctypes.Structure):
        _fields_ = (
            ("s_addr", ctypes.c_uint32),
        )
    _fields_ = (
        ("sin_len", ctypes.c_uint8),
        ("sin_family", ctypes.c_uint8),
        ("sin_port", ctypes.c_uint16),
        ("sin_addr", in_addr_t),
        ("sin_zero", ctypes.c_char * 8),
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

# #define ETHER_ADDR_LEN          6
# typedef struct  ether_header {
# 	u_char  ether_dhost[ETHER_ADDR_LEN];
# 	u_char  ether_shost[ETHER_ADDR_LEN];
# 	u_short ether_type;
# } ether_header_t;
class ether_header_t(ctypes.Structure):
    _fields_ = (
        ("ether_dhost", ctypes.c_ubyte * 6),
        ("ether_shost", ctypes.c_ubyte * 6),
        ("ether_type", ctypes.c_ushort),
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

# struct mac_policy_conf {
#     char *mpc_name;                    // policy name
#     char *mpc_fullname;                // full name
#     char const *const *mpc_labelnames; // managed label namespaces
#     unsigned int mpc_labelname_count;  // number of managed label namespaces
#     struct mac_policy_ops *mpc_ops;    // operation vector
#     int mpc_loadtime_flags;            // load time flags
#     int *mpc_field_off;                // label slot
#     int mpc_runtime_flags;             // run time flags
#     struct mac_policy_conf *mpc_list;  // list reference
#     void *mpc_data;                    // module data
# };
class mac_policy_conf_t(ctypes.Structure):
    _fields_ = (
        ("mpc_name", POINTER64),
        ("mpc_fullname", POINTER64),
        ("mpc_labelnames", POINTER64),
        ("mpc_labelname_count", ctypes.c_uint32),
        ("mpc_ops", POINTER64),
        ("mpc_loadtime_flags", ctypes.c_int32),
        ("mpc_field_off", POINTER64),
        ("mpc_runtime_flags", ctypes.c_int32),
        ("mpc_list", POINTER64),
        ("mpc_data", POINTER64),
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
            if isinstance(getattr(self, field[0]), POINTER64):
                self.ql.log.info("%s: 0x%x" % (field[0], getattr(self, field[0]).value))
            elif isinstance(getattr(self, field[0]), int):
                self.ql.log.info("%s: %d" % (field[0], getattr(self, field[0])))
            elif isinstance(getattr(self, field[0]), bytes):
                self.ql.log.info("%s: %s" % (field[0], getattr(self, field[0]).decode()))

# struct ucred {
# 	TAILQ_ENTRY(ucred)	cr_link; /* never modify this without KAUTH_CRED_HASH_LOCK */
# 	u_long	cr_ref;			/* reference count */
# 	
# struct posix_cred {
# 	uid_t	cr_uid;			/* effective user id */
# 	uid_t	cr_ruid;		/* real user id */
# 	uid_t	cr_svuid;		/* saved user id */
# 	short	cr_ngroups;		/* number of groups in advisory list */
# 	gid_t	cr_groups[NGROUPS];	/* advisory group list */
# 	gid_t	cr_rgid;		/* real group id */
# 	gid_t	cr_svgid;		/* saved group id */
# 	uid_t	cr_gmuid;		/* UID for group membership purposes */
# 	int	cr_flags;		/* flags on credential */
# } cr_posix;
# 	struct label	*cr_label;	/* MAC label */
# 	struct au_session cr_audit;		/* user auditing data */
# };

class ucred_t(ctypes.Structure):
    class cr_entry(ctypes.Structure):
        _fields_ = (
            ("tqe_next", POINTER64),
            ("tqe_prev", POINTER64),
        )
    class posix_cred_t(ctypes.Structure):
        _fields_ = (
            ("cr_uid", ctypes.c_uint32),
            ("cr_ruid", ctypes.c_uint32),
            ("cr_svuid",  ctypes.c_uint32),
            ("cr_ngroups", ctypes.c_short),
            ("cr_groups", ctypes.c_uint32 * 16),
            ("cr_rgid", ctypes.c_uint32),
            ("cr_svgid", ctypes.c_uint32),
            ("cr_gmuid", ctypes.c_uint32),
            ("cr_flags", ctypes.c_int32),
        )
    class au_session_t(ctypes.Structure):
        _fields_ = (
            ("as_aia_p", POINTER64),
            ("as_mask", POINTER64),
        )
    _fields_ = (
        ("cr_link", cr_entry),
        ("cr_ref", ctypes.c_ulong),
        ("cr_posix", posix_cred_t),
        ("cr_label", POINTER64),
        ("cr_audit", au_session_t),
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

# struct label {
#     int	l_flags;
#     union {
#             void	*l_ptr;
#             long	 l_long;
#     }	l_perpolicy[MAC_MAX_SLOTS];
# };

class label_t(ctypes.Structure):
    class l_perpolicy_t(ctypes.Union):
        _fields_ = (
            ("l_ptr", POINTER64),
            ("l_long", ctypes.c_long),
        )
    _fields_ = (
        ("l_flags", ctypes.c_int32),
        ("l_perpolicy", l_perpolicy_t * 7)
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

# struct vnode {
# 	lck_mtx_t v_lock;			/* vnode mutex */
# 	TAILQ_ENTRY(vnode) v_freelist;		/* vnode freelist */
# 	TAILQ_ENTRY(vnode) v_mntvnodes;		/* vnodes for mount point */
#         TAILQ_HEAD(, namecache) v_ncchildren;	/* name cache entries that regard us as their parent */
#         LIST_HEAD(, namecache) v_nclinks;	/* name cache entries that name this vnode */
#         vnode_t	 v_defer_reclaimlist;		/* in case we have to defer the reclaim to avoid recursion */
#         uint32_t v_listflag;			/* flags protected by the vnode_list_lock (see below) */
# 	uint32_t v_flag;			/* vnode flags (see below) */
# 	uint16_t v_lflag;			/* vnode local and named ref flags */
# 	uint8_t	 v_iterblkflags;		/* buf iterator flags */
# 	uint8_t	 v_references;			/* number of times io_count has been granted */
# 	int32_t	 v_kusecount;			/* count of in-kernel refs */
# 	int32_t	 v_usecount;			/* reference count of users */
# 	int32_t	 v_iocount;			/* iocounters */
# 	void *   v_owner;			/* act that owns the vnode */
# 	uint16_t v_type;			/* vnode type */
# 	uint16_t v_tag;				/* type of underlying data */
# 	uint32_t v_id;				/* identity of vnode contents */
# 	union {
# 		struct mount	*vu_mountedhere;/* ptr to mounted vfs (VDIR) */
# 		struct socket	*vu_socket;	/* unix ipc (VSOCK) */
# 		struct specinfo	*vu_specinfo;	/* device (VCHR, VBLK) */
# 		struct fifoinfo	*vu_fifoinfo;	/* fifo (VFIFO) */
# 	        struct ubc_info *vu_ubcinfo;	/* valid for (VREG) */
# 	} v_un;
# 	struct	buflists v_cleanblkhd;		/* clean blocklist head */
# 	struct	buflists v_dirtyblkhd;		/* dirty blocklist head */
# 	struct klist v_knotes;			/* knotes attached to this vnode */
#         kauth_cred_t	v_cred;			/* last authorized credential */
#         kauth_action_t	v_authorized_actions;	/* current authorized actions for v_cred */
#         int		v_cred_timestamp;	/* determine if entry is stale for MNTK_AUTH_OPAQUE */
#         int		v_nc_generation;	/* changes when nodes are removed from the name cache */
# 	int32_t		v_numoutput;			/* num of writes in progress */
# 	int32_t		v_writecount;			/* reference count of writers */
# 	const char *v_name;			/* name component of the vnode */
# 	vnode_t v_parent;			/* pointer to parent vnode */
# 	struct lockf	*v_lockf;		/* advisory lock list head */
# 	int 	(**v_op)(void *);		/* vnode operations vector */
# 	mount_t v_mount;			/* ptr to vfs we are in */
# 	void *	v_data;				/* private data for fs */
# 	struct label *v_label;			/* MAC security label */
# 	vnode_resolve_t v_resolve;		/* trigger vnode resolve info (VDIR only) */
# };
class vnode_t(ctypes.Structure):
    class tailq_entry(ctypes.Structure):
        _fields_ = (
            ("tqe_next", POINTER64),
            ("tqe_prev", POINTER64),
        )
    class tailq_head(ctypes.Structure):
        _fields_ = (
            ("tqh_first", POINTER64),
            ("tqh_last", POINTER64),
        )
    class list_head(ctypes.Structure):
        _fields_ = (
            ("v_nclinks", POINTER64),
        )
    class slist_head(ctypes.Structure):
        _fields_ = (
            ("slh_first", POINTER64),
        )
    class v_un_t(ctypes.Union):
        _fields_ = (
            ("vu_mountedhere", POINTER64),
            ("vu_socket", POINTER64),
            ("vu_specinfo", POINTER64),
            ("vu_fifoinfo", POINTER64),
            ("vu_ubcinfo", POINTER64),
        )
    _fields_ = (
        ("v_lock", POINTER64),
        ("v_freelist", tailq_entry),
        ("v_mntvnodes", tailq_entry),
        ("v_ncchildren", tailq_head),
        ("v_nclinks", list_head),
        ("v_defer_reclaimlist", POINTER64),
        ("v_listflag", ctypes.c_uint32),
        ("v_flag", ctypes.c_uint32),
        ("v_lflag", ctypes.c_uint16),
        ("v_iterblkflags", ctypes.c_uint8),
        ("v_references", ctypes.c_uint8),
        ("v_kusecount", ctypes.c_uint32),
        ("v_usecount", ctypes.c_uint32),
        ("v_iocount", ctypes.c_uint32),
        ("v_owner", POINTER64),
        ("v_type", ctypes.c_uint16),
        ("v_tag", ctypes.c_uint16),
        ("v_id", ctypes.c_uint32),
        ("v_un", v_un_t),
        ("v_cleanblkhd", list_head),
        ("v_dirtyblkhd", list_head),
        ("v_knotes", slist_head),
        ("v_cred", POINTER64),
        ("v_authorized_actions", ctypes.c_int32),
        ("v_cred_timestamp", ctypes.c_int),
        ("v_nc_generation", ctypes.c_int),
        ("v_numoutput", ctypes.c_int32),
        ("v_writecount", ctypes.c_int32),
        ("v_name", POINTER64),
        ("v_parent", POINTER64),
        ("v_lockf", POINTER64),
        ("v_op", POINTER64),
        ("v_mount", POINTER64),
        ("v_data", POINTER64),
        ("v_label", POINTER64),
        ("v_resolve", POINTER64),
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

# struct fileglob {
# 	LIST_ENTRY(fileglob) f_msglist;/* list of active files */
# 	int32_t	fg_flag;		/* see fcntl.h */
# 	int32_t	fg_count;	/* reference count */
# 	int32_t	fg_msgcount;	/* references from message queue */
# 	int32_t fg_lflags;	/* file global flags */
# 	kauth_cred_t fg_cred;	/* credentials associated with descriptor */
# 	const struct fileops {
# 		file_type_t	fo_type;	/* descriptor type */
# 		int	(*fo_read)	(struct fileproc *fp, struct uio *uio,
# 					 int flags, vfs_context_t ctx);
# 		int	(*fo_write)	(struct fileproc *fp, struct uio *uio,
# 					 int flags, vfs_context_t ctx);
# 		int	(*fo_ioctl)	(struct fileproc *fp, u_long com,
# 					 caddr_t data, vfs_context_t ctx);
# 		int	(*fo_select)	(struct fileproc *fp, int which,
# 					 void *wql, vfs_context_t ctx);
# 		int	(*fo_close)	(struct fileglob *fg, vfs_context_t ctx);
# 		int	(*fo_kqfilter)	(struct fileproc *fp, struct knote *kn,
# 					 struct kevent_internal_s *kev, vfs_context_t ctx);
# 		int	(*fo_drain)	(struct fileproc *fp, vfs_context_t ctx);
# 	} *fg_ops;
# 	off_t	fg_offset;
# 	void 	*fg_data;	/* vnode or socket or SHM or semaphore */
# 	void	*fg_vn_data;	/* Per fd vnode data, used for directories */
# 	lck_mtx_t fg_lock;
# 	struct label *fg_label;  /* JMM - use the one in the cred? */
# };

class fileglob_t(ctypes.Structure):
    class list_entry(ctypes.Structure):
        _fields_ = (
            ("le_next", POINTER64),
            ("le_prev", POINTER64),
        )
    _fields_ = (
        ("f_msglist", list_entry),
        ("fg_flag", ctypes.c_int32),
        ("fg_count", ctypes.c_int32),
        ("fg_msgcount", ctypes.c_int32),
        ("fg_lflags", ctypes.c_int32),
        ("fg_cred", POINTER64),
        ("fg_ops", POINTER64),
        ("fg_offset", ctypes.c_int64),
        ("fg_data", POINTER64),
        ("fg_vn_data", POINTER64),
        ("fg_lock", POINTER64),
        ("fg_label", POINTER64),
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

# struct mac_policy_list_element {
#     struct mac_policy_conf *mpc;
# };
# 
# struct mac_policy_list {
#     u_int numloaded;
#     u_int max;
#     u_int maxindex;
#     u_int staticmax;
#     u_int chunks;
#     u_int freehint;
#     struct mac_policy_list_element *entries;
# };
class mac_policy_list_element_t(ctypes.Structure):
    _fields_ = (
        ("mpc", POINTER64),
    )

class mac_policy_list_t(ctypes.Structure):
    _fields_ = (
        ("numloaded", ctypes.c_uint),
        ("max", ctypes.c_uint),
        ("maxindex", ctypes.c_uint),
        ("staticmax", ctypes.c_uint),
        ("chunks", ctypes.c_uint),
        ("freehint", ctypes.c_uint),
        ("entries", POINTER64),
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

# struct ipf_filter {
# 	void		*cookie;
# 	const char	*name;
# 	ipf_input_func	ipf_input;
# 	ipf_output_func	ipf_output;
# 	ipf_detach_func	ipf_detach;
# };
class ipf_filter_t(ctypes.Structure):
    _fields_ = (
        ("cookie", POINTER64),
        ("name", POINTER64),
        ("ipf_input", POINTER64),
        ("ipf_output", POINTER64),
        ("ipf_detach", POINTER64),
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
