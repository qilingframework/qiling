#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

# LONG InterlockedExchange(
#  LONG volatile *Target,
#  LONG          Value
# );
@winsdkapi(cc=STDCALL, params={
    'Target' : POINTER,
    'Value'  : INT # LONG
})
def hook_InterlockedExchange(ql: Qiling, address: int, params):
    Target = params['Target']
    Value = params['Value']

    old = ql.mem.read_ptr(Target, 4)
    ql.mem.write(Target, ql.pack32(Value))

    return old

# LONG InterlockedIncrement(
#  LONG volatile *Target,
# );
@winsdkapi(cc=STDCALL, params={
    'Target' : POINTER
})
def hook_InterlockedIncrement(ql: Qiling, address: int, params):
    Target = params['Target']

    Value = ql.mem.read_ptr(Target, 4)
    Value = (Value + 1) % (1 << 32)     # increment and handle overflow
    ql.mem.write(Target, ql.pack32(Value))

    return Value

# LONG InterlockedDecrement(
#  LONG volatile *Target,
# );
@winsdkapi(cc=STDCALL, params={
    'Target' : POINTER
})
def hook_InterlockedDecrement(ql: Qiling, address: int, params):
    Target = params['Target']

    Value = ql.mem.read_ptr(Target, 4)
    Value = (Value - 1) % (1 << 32)     # increment and handle underflow

    ql.mem.write(Target, ql.pack32(Value))

    return Value

# NTSYSAPI ULONGLONG VerSetConditionMask(
#   ULONGLONG ConditionMask,
#   DWORD     TypeMask,
#   BYTE      Condition
# );
@winsdkapi(cc=STDCALL, params={
    'ConditionMask' : ULONGLONG,
    'TypeMask'      : DWORD,
    'Condition'     : BYTE
})
def hook_VerSetConditionMask(ql: Qiling, address: int, params):
    # ConditionMask = params["ConditionMask"]
    TypeMask = params["TypeMask"]
    Condition = params["Condition"]

    ConditionMask = ql.os.hooks_variables.get("ConditionMask", {})

    if TypeMask == 0:
        ret = ConditionMask
    else:
        Condition &= VER_CONDITION_MASK

        if Condition == 0:
            ret = ConditionMask
        else:
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
