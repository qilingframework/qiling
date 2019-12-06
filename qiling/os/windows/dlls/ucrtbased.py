#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.memory import align
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *

#_ACRTIMP int __cdecl __stdio_common_vfprintf(
#    _In_                                    unsigned __int64 _Options,
#    _Inout_                                 FILE*            _Stream,
#    _In_z_ _Printf_format_string_params_(2) char const*      _Format,
#    _In_opt_                                _locale_t        _Locale,
#                                            va_list          _ArgList
#    );
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "_Options": UINT,
    "_Stream": POINTER,
    "_Format": POINTER,
    "_Locale": POINTER,
    "wat": POINTER
})
def hook___stdio_common_vfprintf(ql, address, params):
    #ql.print(ql.uc.mem_read(params['_Format'], 0x20))
    #The parameter count seems to differ between x86 and x64 versions
    if ql.pointersize == 8:
        ql.stack_push(0)
    return 0

#FILE* __cdecl __acrt_iob_func(unsigned _Ix);
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "_Ix": UINT
})
def hook___acrt_iob_func(ql, address, params):
    addr = ql.heap.mem_alloc(ql.pointersize)
    return addr

