#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *


# int WSAStartup(
#  WORD      wVersionRequired,
#  LPWSADATA lpWSAData
# );
@winapi(cc=STDCALL, params={"wVersionRequired": DWORD, "LPWSADATA": STRING})
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
@winapi(
    STDCALL,
    params={
        "af": INT,
        "type": INT,
        "protocol": INT,
        "lpProtocolInfo": POINTER,
        "g": INT,
        "dwFlags": INT,
    },
)
def hook_WSASocketA(ql, address, params):
    return 0


# int WSAAPI connect(
#  SOCKET         s,
#  const sockaddr *name,
#  int            namelen
# );
@winapi(cc=STDCALL, params={"s": INT, "name": POINTER, "namelen": INT})
def hook_connect(ql, address, params):
    sin_family =ql.mem.read(params["name"], 1)[0]
    sin_port = int.from_bytes(ql.mem.read(params["name"] + 2, 2), byteorder="big")
    if sin_family == 0x17:  # IPv6
        segments = list(map("{:02x}".format,ql.mem.read(params["name"] + 8, 16)))
        sin_addr = ":".join(["".join(x) for x in zip(segments[0::2], segments[1::2])])
    elif sin_family == 0x2:  # IPv4
        sin_addr = ".".join(
            [str(octet) for octet in ql.mem.read(params["name"] + 4, 4)]
        )
    else:
        print("[!] sockaddr sin_family unhandled variant")
        return 0
    print(
        f"0x{params['name']:08x}: sockaddr_in{6 if sin_family == 0x17 else ''}",
        f"{{sin_family=0x{sin_family:02x}, sin_port={sin_port}, sin_addr={sin_addr}}}",
        sep="",
    )
    return 0
