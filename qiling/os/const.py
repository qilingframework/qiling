#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

# global primitive types used in fcalls and api hooks.
#
# operating systems may map their own types to these, or create additional ones
# with custom resolvers (see: QlOs)
PARAM_INT8  = 1
PARAM_INT16 = 2
PARAM_INT32 = 3
PARAM_INT64 = 4
PARAM_INTN  = 5

# a generic pointer type that may be used to index pointed types
PARAM_PTRX  = 128

# common alises to primitive types.
# TODO: let each OS define its own aliases and types
BYTE      = PARAM_INT8
DWORD     = PARAM_INT32
INT       = PARAM_INT32
UINT      = PARAM_INT32
BOOL      = PARAM_INT32
LONGLONG  = PARAM_INT64
ULONGLONG = PARAM_INT64
SIZE_T    = PARAM_INTN
POINTER   = PARAM_INTN
HANDLE    = PARAM_INTN
STRING    = PARAM_PTRX + 1
WSTRING   = PARAM_PTRX + 2
GUID      = PARAM_PTRX + 3
