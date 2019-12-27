socket_family = {
        'AF_UNSPEC'    : 0x0,
        'AF_INET'      : 0x2,
        'AF_AX25'      : 0x3,
        'AF_IPX'       : 0x4,
        'AF_APPLETALK' : 0x5,
        'AF_NETROM'    : 0x6,
        'AF_BRIDGE'    : 0x7,
        'AF_AAL5'      : 0x8,
        'AF_X25'       : 0x9,
        'AF_INET6'     : 0xa,
        'AF_MAX'       : 0xc,
    }

socket_types = {
        'SOCK_STREAM'    : 0x1,
        'SOCK_DGRAM'     : 0x2,
        'SOCK_RAW'       : 0x3,
        'SOCK_RDM'       : 0x4,
        'SOCK_SEQPACKET' : 0x5,
        'SOCK_PACKET'    : 0xa,
        }

socket_const = { v:k for k, v in ({**socket_types, **socket_family}).items() }
