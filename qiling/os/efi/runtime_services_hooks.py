from qiling.const import *
from qiling.os.efi.fncc import *
from qiling.os.efi.efi_types_64 import *
from qiling.os.windows.fncc import *

@dxeapi(params={
    "a0": POINTER, #POINTER_T(struct_EFI_TIME)
    "a1": POINTER, #POINTER_T(struct_EFI_TIME_CAPABILITIES)
})
def hook_GetTime(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(struct_EFI_TIME)
})
def hook_SetTime(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(ctypes.c_ubyte)
    "a1": POINTER, #POINTER_T(ctypes.c_ubyte)
    "a2": POINTER, #POINTER_T(struct_EFI_TIME)
})
def hook_GetWakeupTime(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": POINTER, #POINTER_T(struct_EFI_TIME)
})
def hook_SetWakeupTime(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
    "a2": UINT,
    "a3": POINTER, #POINTER_T(struct_EFI_MEMORY_DESCRIPTOR)
})
def hook_SetVirtualAddressMap(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_ConvertPointer(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "VariableName": WSTRING,
    "VendorGuid": GUID,
    "Attributes": POINTER,
    "DataSize": POINTER,
    "Data": POINTER
})
def hook_GetVariable(self, address, params):
    if params['VariableName'] in self.ql.var_store:
        var = self.ql.var_store[params['VariableName']]
        read_len = self.read_int(params['DataSize'])
        read_len = min(len(var), read_len)
        self.write_int(params['DataSize'], read_len)
        if params['Data'] != 0:
            self.ql.mem.write(params['Data'], var[:read_len])
        return read_len
    return -1

@dxeapi(params={
    "a0": POINTER, #POINTER_T(ctypes.c_uint64)
    "a1": POINTER, #POINTER_T(ctypes.c_uint16)
    "a2": GUID,
})
def hook_GetNextVariableName(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(ctypes.c_uint16)
    "a1": GUID,
    "a2": UINT,
    "a3": ULONGLONG,
    "a4": POINTER, #POINTER_T(None)
})
def hook_SetVariable(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(ctypes.c_uint32)
})
def hook_GetNextHighMonotonicCount(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
    "a2": ULONGLONG,
    "a3": POINTER, #POINTER_T(None)
})
def hook_ResetSystem(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(POINTER_T(struct_EFI_CAPSULE_HEADER))
    "a1": ULONGLONG,
    "a2": ULONGLONG,
})
def hook_UpdateCapsule(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(POINTER_T(struct_EFI_CAPSULE_HEADER))
    "a1": ULONGLONG,
    "a2": POINTER, #POINTER_T(ctypes.c_uint64)
    "a3": POINTER, #POINTER_T(enum_73)
})
def hook_QueryCapsuleCapabilities(self, address, params):
    return self.EFI_SUCCESS

@dxeapi(params={
    "a0": UINT,
    "a1": POINTER, #POINTER_T(ctypes.c_uint64)
    "a2": POINTER, #POINTER_T(ctypes.c_uint64)
    "a3": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_QueryVariableInfo(self, address, params):
    return self.EFI_SUCCESS



def hook_EFI_RUNTIME_SERVICES(start_ptr, ql):
    efi_runtime_services = EFI_RUNTIME_SERVICES()
    ptr = start_ptr
    pointer_size = 8
    efi_runtime_services.GetTime = ptr
    ql.hook_address(hook_GetTime, ptr)
    ptr += pointer_size
    efi_runtime_services.SetTime = ptr
    ql.hook_address(hook_SetTime, ptr)
    ptr += pointer_size
    efi_runtime_services.GetWakeupTime = ptr
    ql.hook_address(hook_GetWakeupTime, ptr)
    ptr += pointer_size
    efi_runtime_services.SetWakeupTime = ptr
    ql.hook_address(hook_SetWakeupTime, ptr)
    ptr += pointer_size
    efi_runtime_services.SetVirtualAddressMap = ptr
    ql.hook_address(hook_SetVirtualAddressMap, ptr)
    ptr += pointer_size
    efi_runtime_services.ConvertPointer = ptr
    ql.hook_address(hook_ConvertPointer, ptr)
    ptr += pointer_size
    efi_runtime_services.GetVariable = ptr
    ql.hook_address(hook_GetVariable, ptr)
    ptr += pointer_size
    efi_runtime_services.GetNextVariableName = ptr
    ql.hook_address(hook_GetNextVariableName, ptr)
    ptr += pointer_size
    efi_runtime_services.SetVariable = ptr
    ql.hook_address(hook_SetVariable, ptr)
    ptr += pointer_size
    efi_runtime_services.GetNextHighMonotonicCount = ptr
    ql.hook_address(hook_GetNextHighMonotonicCount, ptr)
    ptr += pointer_size
    efi_runtime_services.ResetSystem = ptr
    ql.hook_address(hook_ResetSystem, ptr)
    ptr += pointer_size
    efi_runtime_services.UpdateCapsule = ptr
    ql.hook_address(hook_UpdateCapsule, ptr)
    ptr += pointer_size
    efi_runtime_services.QueryCapsuleCapabilities = ptr
    ql.hook_address(hook_QueryCapsuleCapabilities, ptr)
    ptr += pointer_size
    efi_runtime_services.QueryVariableInfo = ptr
    ql.hook_address(hook_QueryVariableInfo, ptr)
    ptr += pointer_size
    return (ptr, efi_runtime_services)

