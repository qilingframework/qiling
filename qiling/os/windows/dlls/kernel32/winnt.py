#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

dllname = 'kernel32_dll'

# LONG InterlockedExchange(
#  LONG volatile *Target,
#  LONG          Value
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"Target": POINTER, "Value": UINT})
def hook_InterlockedExchange(ql, address, params):
    old = int.from_bytes(ql.mem.read(params['Target'], ql.pointersize), byteorder='little')
    ql.mem.write(params['Target'], params['Value'].to_bytes(length=ql.pointersize, byteorder='little'))
    return old


# LONG InterlockedIncrement(
#  LONG volatile *Target,
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"Target": POINTER})
def hook_InterlockedIncrement(ql, address, params):
    val = int.from_bytes(ql.mem.read(params['Target'], 4), byteorder='little')
    val += 1 & (2 ** 32)  # increment and overflow back to 0 if applicable
    ql.mem.write(params['Target'], val.to_bytes(length=4, byteorder='little'))
    return val


# LONG InterlockedDecrement(
#  LONG volatile *Target,
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"Target": POINTER})
def hook_InterlockedDecrement(ql, address, params):
    val = int.from_bytes(ql.mem.read(params['Target'], 4), byteorder='little')
    val -= 1
    if val == -1:
        val = 0xFFFFFFFF
    ql.mem.write(params['Target'], val.to_bytes(length=4, byteorder='little'))
    return val


# NTSYSAPI ULONGLONG VerSetConditionMask(
#   ULONGLONG ConditionMask, => 64bit param
#   DWORD     TypeMask,
#   BYTE      Condition
# );
@winsdkapi(cc=STDCALL, dllname=dllname, replace_params={"ConditionMask": ULONGLONG, "TypeMask": DWORD, "Condition": BYTE})
def hook_VerSetConditionMask(ql, address, params):
    # ConditionMask = params["ConditionMask"]
    TypeMask = params["TypeMask"]
    Condition = params["Condition"]
    mask = params["ConditionMask"]
    ConditionMask = ql.os.hooks_variables.get("ConditionMask", {})
    if TypeMask == 0:
        ret = ConditionMask
    else:
        Condition &= VER_CONDITION_MASK
        if Condition == 0:
            ret = ConditionMask
        else:
            ullCondMask = Condition
            if TypeMask & VER_PRODUCT_TYPE:
                # ConditionMask |= ullCondMask << (7 * VER_NUM_BITS_PER_CONDITION_MASK)
                ConditionMask[VER_PRODUCT_TYPE] = Condition
            elif TypeMask & VER_SUITENAME:
                # ConditionMask |= ullCondMask << (6 * VER_NUM_BITS_PER_CONDITION_MASK)
                ConditionMask[VER_SUITENAME] = Condition
            elif TypeMask & VER_SERVICEPACKMAJOR:
                # ConditionMask |= ullCondMask << (5 * VER_NUM_BITS_PER_CONDITION_MASK)
                ConditionMask[VER_SERVICEPACKMAJOR] = Condition
            elif TypeMask & VER_SERVICEPACKMINOR:
                # ConditionMask |= ullCondMask << (4 * VER_NUM_BITS_PER_CONDITION_MASK)
                ConditionMask[VER_SERVICEPACKMINOR] = Condition
            elif TypeMask & VER_PLATFORMID:
                # ConditionMask |= ullCondMask << (3 * VER_NUM_BITS_PER_CONDITION_MASK)
                ConditionMask[VER_PLATFORMID] = Condition
            elif TypeMask & VER_BUILDNUMBER:
                # ConditionMask |= ullCondMask << (2 * VER_NUM_BITS_PER_CONDITION_MASK)
                ConditionMask[VER_BUILDNUMBER] = Condition
            elif TypeMask & VER_MAJORVERSION:
                # ConditionMask |= ullCondMask << (1 * VER_NUM_BITS_PER_CONDITION_MASK)
                ConditionMask[VER_MAJORVERSION] = Condition
            elif TypeMask & VER_MINORVERSION:
                # ConditionMask |= ullCondMask << (0 * VER_NUM_BITS_PER_CONDITION_MASK)
                ConditionMask[VER_MINORVERSION] = Condition
            ret = 1
    # ConditionMask should be updated locally
    # https://docs.microsoft.com/it-it/windows/win32/sysinfo/verifying-the-system-version
    # But since we don't have the pointer to the variable, an hack is to use the environment.
    # Feel free to push a better solution
    # Since I can't work with bits, and since we had to work with the environment anyway, let's use a dict
    ql.os.hooks_variables["ConditionMask"] = ConditionMask
    return ret
