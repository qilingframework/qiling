import struct
from qiling.const import *
from qiling.os.windows.fncc import *

def dxeapi(param_num=None, params=None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            class hook_context:
                def __init__(self, ql):
                    self.ql = ql
                    self.PE_RUN = True
                def write_int(self, address, num):
                    if self.ql.archendian == QL_ENDIAN_EL:
                        self.ql.mem.write(address, struct.pack('<Q',(num)))
                    else:
                        self.ql.mem.write(address, struct.pack('>Q',(num)))
                def read_int(self, address):
                    if self.ql.archendian == QL_ENDIAN_EL:
                        return struct.unpack('<Q', self.ql.mem.read(address, 8))[0]
                    else:
                        return struct.unpack('>Q',self.ql.mem.read(address, 8))[0]
            self = hook_context(args[0])
            arg = (self, self.ql.pc, {})
            return x8664_fastcall(self, param_num, params, func, arg, kwargs)

        return wrapper

    return decorator
