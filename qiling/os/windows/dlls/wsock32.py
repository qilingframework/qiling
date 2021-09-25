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
    sin_family = ql.mem.read(params["name"], 1)[0]
    sin_port = int.from_bytes(ql.mem.read(params["name"] + 2, 2), byteorder="big")

    if sin_family == 0x17:  # IPv6
        segments = list(map("{:02x}".format, ql.mem.read(params["name"] + 8, 16)))
        sin_addr = ":".join(["".join(x) for x in zip(segments[0::2], segments[1::2])])

    elif sin_family == 0x2:  # IPv4
        sin_addr = ".".join((str(octet) for octet in ql.mem.read(params["name"] + 4, 4)))
    else:
        ql.log.debug("sockaddr sin_family unhandled variant")
        return 0

    ql.log.debug(f"{params['name']:#010x}: sockaddr_in{6 if sin_family == 0x17 else ''}",
              f"{{sin_family={sin_family:#04x}, sin_port={sin_port}, sin_addr={sin_addr}}}",
              sep="")
    return 0

# hostent * gethostbyname(
#  const char *name
# );
@winsdkapi(cc=WSAAPI, params={
    'name' : POINTER
})
def hook_gethostbyname(ql: Qiling, address: int, params):
    ip_str = ql.os.profile.get("NETWORK", "dns_response_ip")
    ip = bytes((int(octet) for octet in reversed(ip_str.split('.'))))

    name_ptr = params["name"]
    # params["name"] = ql.os.utils.read_cstring(name_ptr)

    hostnet = Hostent(ql, name_ptr, 0, 2, 4, ip)
    hostnet_addr = ql.os.heap.alloc(hostnet.size)
    hostnet.write(hostnet_addr)

    return hostnet_addr
