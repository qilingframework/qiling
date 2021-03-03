#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import json, os

from typing import Union, Optional, Mapping, MutableMapping

from qiling import Qiling
from qiling.const import QL_INTERCEPT
from qiling.extensions.windows_sdk import winsdk_path
import qiling.os.const as const

def replacetype(ptype: str, specialtype: Mapping) -> Optional[int]:
    if ptype in specialtype:
         ptype = specialtype[ptype]

    if ptype in const.reptypedict:
        return const.reptypedict[ptype]

    return None

__sdk_cache: MutableMapping[str, Mapping] = {}

# <workaround>
__undefined_types: MutableMapping[str, int] = {}

def __log_udnefined_type(ptype: str):
    if ptype not in __undefined_types:
        __undefined_types[ptype] = 0

    __undefined_types[ptype] += 1

def __print_undefined_types():
    items = sorted(__undefined_types.items(), key = lambda p: p[1], reverse=True)

    maxlen = max(len(name) for name, _ in items)
    maxlenc = len(str(max(count for _, count in items)))

    print(f'undefined types:')
    for name, count in items:
        print(f' - {name:<{maxlen}s} : {count:{maxlenc}d}')

# </workaround>

def __load_winsdk_defs(dllname: str) -> Mapping:
    if dllname not in __sdk_cache:
        json_file = os.path.join(winsdk_path, 'defs', f'{dllname}.json')
        defs: Mapping[str, Mapping] = {}

        if os.path.exists(json_file):
            with open(json_file, 'r') as f:
                obj = json.load(f)

            for fname, fparams in obj.items():
                fdef: Mapping[str, Union[int, dict]] = {}

                for p in fparams:
                    pname = p['name']
                    ptype = p['type']

                    if type(ptype) is str:
                        #ptype = getattr(const, ptype, None) or const.reptypedict[ptype]

                        # <workaround>
                        _ptype = getattr(const, ptype, None) or const.reptypedict.get(ptype)

                        if _ptype is None:
                            __log_udnefined_type(ptype)
                        # </workaround>

                    fdef[pname] = ptype

                defs[fname] = fdef

        __sdk_cache[dllname] = defs

        __print_undefined_types()

    return __sdk_cache[dllname]

# x86/x8664 PE should share Windows APIs
def winsdkapi(cc: int, param_num: int = None, dllname: str = None, replace_params_type: Mapping[str, str] = {}, replace_params = {}, passthru: bool = False):
    """
    @cc: windows api calling convention, only x86 needs this, x64 is always fastcall
    @param_num: the number of function params, used by variadic functions, e.g printf
    @dllname: the name of function
    @replace_params_type: customize replace type, e.g specialtype={'int':'UINT'} means repalce 'int' to 'UINT'
    @replace_params: customize replace param_name's type, e.g specialtypeEx={'time':'int'} means
                replace the original type of time to int
    """
    def decorator(func):
        def wrapper(ql: Qiling, pc: int, api_name: str):
            params = {}

            # ---------- params types substitution (to be removed eventually) ----------
            if dllname is not None:
                funcdefs = __load_winsdk_defs(dllname)

                if not funcdefs:
                    ql.log.info(f'defs for {dllname} not found')

                if api_name in funcdefs:
                    paramlist = funcdefs[api_name]

                    if len(replace_params) == len(paramlist):
                        params = replace_params

                        # substitue string type names (if any) with their actual type value
                        for pname, ptype in params.items():
                            if type(ptype) is str:
                                params[pname] = replacetype(ptype, replace_params_type)

                                if params[pname] is None:
                                    ql.log.exception(f'no replacement found for type "{ptype}" ({api_name}, {dllname})')

                    else:
                        for pname, ptype in paramlist.items():
                            # function prototype has no arguments
                            if pname == 'VOID' or replace_params.get(pname) == '':
                                params = {}
                                break

                            # substitue this parameter type, if its name was found in the replacements mapping
                            elif pname in replace_params:
                                params[pname] = replace_params[pname]

                            else:
                                if type(ptype) is dict:
                                    ptype = ptype['name']

                                params[pname] = replacetype(ptype, replace_params_type)

                                if params[pname] is None:
                                    ql.log.exception(f'no replacement found for type "{ptype}" ({api_name}, {dllname})')
                else:
                    params = replace_params
            else:
                params = replace_params
            # --------------------------------------------------------------------------

            ql.os.fcall = ql.os.fcall_select(cc)

            onenter = ql.os.user_defined_api[QL_INTERCEPT.ENTER].get(api_name)
            onexit = ql.os.user_defined_api[QL_INTERCEPT.EXIT].get(api_name)

            return ql.os.call(pc, func, params, onenter, onexit, passthru=passthru)

        return wrapper

    return decorator
