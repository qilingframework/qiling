#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os
import json
import struct
from functools import wraps

from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.const import *
from qiling.exception import *


def replacetype(type, specialtype=None):
    if specialtype is None:
        specialtype = {}

    if type in reptypedict.keys():
        if type not in specialtype.keys():
            return reptypedict[type]
        else:
            return specialtype[type]
    else:
        return type

# x86/x8664 PE should share Windows APIs
def winsdkapi(cc, param_num=None, dllname=None, specialtype=None, specialtypeEx=None, defparams=None):
    """
    @cc: windows api calling convention, only x86 needs this, x64 is always fastcall
    @param_num: the number of function params, used by variadic functions, e.g printf
    @dllname: the name of function
    @funcname: function's name
    @specialtype: customize replace type, e.g specialtype={'int':'UINT'} means repalce 'int' to 'UINT'
    @specialtypeEx: customize replace param_name's type, e.g specialtypeEx={'time':'int'} means
                replace the original type of time to int
    @defparams: customize all params and their type
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            funcname = func.__name__[5:]
            params = {}
            paramlist = []
            ql = args[0]
            if defparams is not None:
                params = defparams
            else:
                if dllname is not None:
                    windows_abspath = os.path.dirname(os.path.abspath(__file__))
                    winsdk_path = os.path.join(windows_abspath[:-11], 'extensions', 'windows_sdk', 'defs', dllname + '.json')
                    if os.path.exists(winsdk_path):
                        f = open(winsdk_path, 'r')
                        funclist = json.load(f)
                        paramlist = funclist[funcname]
                    for para in paramlist:
                        name = list(para.values())[0]
                        if name == 'VOID':
                            params = {}
                            break
                        elif specialtypeEx is not None and name in specialtypeEx.keys():
                            type = specialtypeEx[name]
                        else:
                            type = list(para.values())[1]
                            if isinstance(type, dict):
                                type = replacetype(type['name'], specialtype)
                            else:
                                type = replacetype(list(para.values())[1], specialtype)
                        params[name] = eval(type)

            if ql.archtype == QL_ARCH.X86:
                if cc == STDCALL:
                    return ql.os.x86_stdcall(param_num, params, func, args, kwargs)
                elif cc == CDECL:
                    return ql.os.x86_cdecl(param_num, params, func, args, kwargs)
            elif ql.archtype == QL_ARCH.X8664:
                return ql.os.x8664_fastcall(param_num, params, func, args, kwargs)
            else:
                raise QlErrorArch("[!] Unknown self.ql.arch")
        return wrapper

    return decorator
