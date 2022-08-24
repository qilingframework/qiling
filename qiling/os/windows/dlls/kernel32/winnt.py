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
    ql.mem.write_ptr(Target, Value, 4)

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
    Value = (Value + 1) % (1 << 32)     # increase and handle overflow
    ql.mem.write_ptr(Target, Value, 4)

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
    Value = (Value - 1) % (1 << 32)     # decrease and handle underflow
    ql.mem.write_ptr(Target, Value, 4)

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
    # see: https://docs.microsoft.com/en-us/windows/win32/sysinfo/verifying-the-system-version

    ConditionMask = params['ConditionMask']
    TypeMask = params['TypeMask']
    Condition = params['Condition']

    Condition &= VER_CONDITION_MASK

    if Condition:
        for i in range(8):
            if TypeMask & (1 << i):
                ConditionMask |= Condition << (i * VER_NUM_BITS_PER_CONDITION_MASK)

    return ConditionMask
