#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
import struct
import base64
from qiling.os.windows.fncc import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.handle import *
from qiling.os.windows.const import *


# BOOL CryptStringToBinaryA(
#   LPCSTR pszString,
#   DWORD  cchString,
#   DWORD  dwFlags,
#   BYTE   *pbBinary,
#   DWORD  *pcbBinary,
#   DWORD  *pdwSkip,
#   DWORD  *pdwFlags
# );
@winapi(cc=STDCALL, params={
    "pszString": STRING,
    "cchString": DWORD,
    "dwFlags": DWORD,
    "pbBinary": POINTER,
    "pcbBinary": POINTER,
    "pdwSkip": POINTER,
    "pdwFlags": POINTER
})
def hook_CryptStringToBinaryA(self, address, params):
    flag_src = params["dwFlags"]
    string_src = params["pszString"]
    size_src = params["cchString"]
    size_dst_pointer = params["pcbBinary"]
    string_dst = params["pbBinary"]
    flag_dst = params["pdwFlags"]

    size_dst = int.from_bytes(self.mem.read(size_dst_pointer, 4), byteorder="little")
    if size_dst != 0 and size_dst < size_src:
        raise QlErrorNotImplemented("[!] API not implemented")
    if flag_src == CRYPT_STRING_BASE64:
        # Had a padding error, hope this always works
        add_pad = 4 - (len(string_src) % 4)
        if add_pad != 4:
            string_src += "=" * add_pad
        output = base64.b64decode(string_src).decode("utf-16le") + "\x00"
    else:
        self.ql.dprint(D_PROT, "Flag")
        self.ql.dprint(D_PROT, flag_src)
        raise QlErrorNotImplemented("[!] API not implemented")

    if string_dst == 0:
        # Only wants the length
        return len(output)
    else:
        if flag_dst != 0:
            # Is optional
            self.ql.mem.write(flag_dst, flag_src.to_bytes(length=4, byteorder='little'))
        # Write size
        self.ql.mem.write(size_dst_pointer, len(output).to_bytes(length=4, byteorder='little'))
        # Write result
        self.ql.mem.write(string_dst, bytes(output, encoding="utf-16le"))
    return 1
