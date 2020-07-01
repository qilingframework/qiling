#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *
from qiling.os.windows.structs import *

dllname = 'ws2_32_dll'

# int WSAStartup(
#  WORD      wVersionRequired,
#  LPWSADATA lpWSAData
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_WSAStartup(ql, address, params):
    return 0


# SOCKET WSAAPI WSASocketA(
#  int                 af,
#  int                 type,
#  int                 protocol,
#  LPWSAPROTOCOL_INFOA lpProtocolInfo,
#  GROUP               g,
#  DWORD               dwFlags
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'DWORD': 'INT'})
def hook_WSASocketA(ql, address, params):
    return 0


# int WSAAPI connect(
#  SOCKET         s,
#  const sockaddr *name,
#  int            namelen
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_connect(ql, address, params):
    sin_family = ql.mem.read(params["name"], 1)[0]
    sin_port = int.from_bytes(ql.mem.read(params["name"] + 2, 2), byteorder="big")

    if sin_family == 0x17:  # IPv6
        segments = list(map("{:02x}".format, ql.mem.read(params["name"] + 8, 16)))
        sin_addr = ":".join(["".join(x) for x in zip(segments[0::2], segments[1::2])])
    elif sin_family == 0x2:  # IPv4
        sin_addr = ".".join(
            [str(octet) for octet in ql.mem.read(params["name"] + 4, 4)]
        )
    else:
        ql.dprint(D_INFO, "[!] sockaddr sin_family unhandled variant")
        return 0

    ql.dprint(D_INFO,
              f"0x{params['name']:08x}: sockaddr_in{6 if sin_family == 0x17 else ''}",
              f"{{sin_family=0x{sin_family:02x}, sin_port={sin_port}, sin_addr={sin_addr}}}",
              sep="",
              )
    return 0


# hostent * gethostbyname(
#  const char *name
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params_type={'char': 'POINTER'})
def hook_gethostbyname(ql, address, params):
    ip_str = ql.os.profile.getint("NETWORK", "dns_response_ip")
    ip = bytes([int(octet) for octet in ip_str.split('.')[::-1]])
    name_ptr = params["name"]
    params["name"] = ql.os.read_cstring(name_ptr)
    hostnet = Hostent(ql, name_ptr, 0, 2, 4, ip)
    hostnet_addr = ql.os.heap.alloc(hostnet.size)
    hostnet.write(hostnet_addr)

    return hostnet_addr
