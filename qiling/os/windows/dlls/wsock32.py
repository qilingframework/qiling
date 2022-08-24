#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *
from qiling.os.windows.structs import *

WSAAPI = STDCALL

# int WSAStartup(
#  WORD      wVersionRequired,
#  LPWSADATA lpWSAData
# );
@winsdkapi(cc=WSAAPI, params={
    'wVersionRequested' : WORD,
    'lpWSAData'         : LPWSADATA
})
def hook_WSAStartup(ql: Qiling, address: int, params):
    return 0

# SOCKET WSAAPI WSASocketA(
#  int                 af,
#  int                 type,
#  int                 protocol,
#  LPWSAPROTOCOL_INFOA lpProtocolInfo,
#  GROUP               g,
#  DWORD               dwFlags
# );
@winsdkapi(cc=WSAAPI, params={
    'af'             : INT,
    'type'           : INT,
    'protocol'       : INT,
    'lpProtocolInfo' : LPWSAPROTOCOL_INFOA,
    'g'              : GROUP,
    'dwFlags'        : DWORD
})
def hook_WSASocketA(ql: Qiling, address: int, params):
    return 0

# int WSAAPI connect(
#  SOCKET         s,
#  const sockaddr *name,
#  int            namelen
# );
@winsdkapi(cc=WSAAPI, params={
    's'       : SOCKET,
    'name'    : POINTER,
    'namelen' : INT
})
def hook_connect(ql: Qiling, address: int, params):
    name = params["name"]
    namelen = params['namelen']

    # sockaddr structure type needs to be defined based on the family field value.
    # both types (for ipv4 and ipv6) have it on the same offset, so we assume ipv4
    # by default for convinience.
    sockaddr_struct = make_sockaddr_in()

    # sockaddr is not based on BaseStruct, so we have to read it manually
    sockaddr_data = ql.mem.read(name, namelen)
    sockaddr_obj = sockaddr_struct.from_buffer_copy(sockaddr_data[:ctypes.sizeof(sockaddr_struct)])

    sin_family = sockaddr_obj.sin_family
    sin_port = sockaddr_obj.sin_port

    if sin_family == 0x17:  # IPv6
        sockaddr_struct = make_sockaddr_in6()
        sockaddr_obj = sockaddr_struct.from_buffer_copy(sockaddr_data[:ctypes.sizeof(sockaddr_struct)])

        # read address bytes and show them as pairs
        segments = [f'{b:02x}' for b in sockaddr_obj.sin6_addr.Byte]
        sin_addr = ':'.join(''.join(x) for x in zip(segments[0::2], segments[1::2]))

    elif sin_family == 0x2:  # IPv4
        a = sockaddr_obj.sin_addr
        sin_addr = '.'.join((a.s_b1, a.s_b2, a.s_b3, a.s_b4))

    else:
        ql.log.debug("sockaddr sin_family unhandled variant")
        return 0

    ql.log.debug(f'{sockaddr_struct.__name__} @ {name:#010x} : {sin_family=:#04x}, {sin_port=}, {sin_addr=}')

    # FIXME: wait.. we just printed stuff out, and did not connect anywhere..

    return 0

# hostent * gethostbyname(
#  const char *name
# );
@winsdkapi(cc=WSAAPI, params={
    'name' : POINTER
})
def hook_gethostbyname(ql: Qiling, address: int, params):
    name_ptr = params['name']

    # set string value back to arg to let it show on log
    params['name'] = ql.os.utils.read_cstring(name_ptr)

    # prepare the ip address data bytes
    ip_str = ql.os.profile.get('NETWORK', 'dns_response_ip')
    ip = bytes((int(octet) for octet in reversed(ip_str.split('.'))))

    # allocate room for the ip address data bytes
    list_item = ql.os.heap.alloc(len(ip))
    ql.mem.write(list_item, ip)

    # allocate room for a list with one item, followed by a nullptr sentinel
    addr_list = ql.os.heap.alloc(2 * ql.arch.pointersize)

    ql.mem.write_ptr(addr_list + 0 * ql.arch.pointersize, list_item)
    ql.mem.write_ptr(addr_list + 1 * ql.arch.pointersize, 0)

    # we need a pointer to a nullptr; reuse the sentinel address for that
    d_nullptr = addr_list + 1 * ql.arch.pointersize

    hostent_struct = make_hostent(ql.arch.bits)
    hostnet_addr = ql.os.heap.alloc(hostent_struct.sizeof())

    hostent_obj = hostent_struct(
        h_name      = name_ptr,
        h_aliases   = d_nullptr,
        h_addrtype  = 2,  # AF_INET
        h_length    = len(ip),
        h_addr_list = addr_list
    )

    hostent_obj.save_to(ql.mem, hostnet_addr)

    return hostnet_addr
