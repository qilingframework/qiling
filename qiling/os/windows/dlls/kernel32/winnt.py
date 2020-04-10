#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

# LONG InterlockedExchange(
#  LONG volatile *Target,
#  LONG          Value
# );


@winapi(cc=STDCALL, params={
    "Target": POINTER,
    "Value": UINT
})
def hook_InterlockedExchange(self, address, params):
    old = int.from_bytes(self.ql.mem.read(params['Target'], self.ql.pointersize), byteorder='little')
    self.ql.mem.write(params['Target'], params['Value'].to_bytes(length=self.ql.pointersize, byteorder='little'))
    return old


# LONG InterlockedIncrement(
#  LONG volatile *Target,
# );
@winapi(cc=STDCALL, params={
    "Target": POINTER
})
def hook_InterlockedIncrement(self, address, params):
    val = int.from_bytes(self.ql.mem.read(params['Target'], self.ql.pointersize), byteorder='little')
    val += 1 & (2 ** self.ql.pointersize * 8)  # increment and overflow back to 0 if applicable
    self.ql.mem.write(params['Target'], val.to_bytes(length=self.ql.pointersize, byteorder='little'))
    return val


# NTSYSAPI ULONGLONG VerSetConditionMask(
#   ULONGLONG ConditionMask, => 64bit param
#   DWORD     TypeMask,
#   BYTE      Condition
# );
@winapi(cc=STDCALL, params={
    "ConditionMask": ULONGLONG,
    "TypeMask": DWORD,
    "Condition": BYTE
})
def hook_VerSetConditionMask(self, address, params):
    # ConditionMask = params["ConditionMask"]
    TypeMask = params["TypeMask"]
    Condition = params["Condition"]
    ConditionMask = self.hooks_variables.get("ConditionMask", {})
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
    self.hooks_variables["ConditionMask"] = ConditionMask
    return ret
