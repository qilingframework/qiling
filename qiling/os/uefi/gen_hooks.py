#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# generate hook files: boot_services_hooks.py & runtime_services_hooks.

import ctypes
from uefi_types_64 import *

def generate_hooks(cls_name, stram):
    cls = eval(cls_name)
    print('# NOTE: Autogen from gen_hooks.py. DO NOT MODIFY!\n', file=stram)
    print('from qiling.const import *\n', file=stram)
    print('from qiling.os.uefi.fncc import *\n', file=stram)
    print('from qiling.os.uefi.uefi_types_64 import *\n', file=stram)
    print('from qiling.os.windows.fncc import *\n', file=stram)

    gen_func_str = f'\n\ndef hook_{cls_name}(start_ptr, ql):\n'
    class_instance_name = cls_name.lower()
    gen_func_str += f'\t{class_instance_name} = {cls_name}()\n'
    gen_func_str += f'\tptr = start_ptr\n'
    gen_func_str += f'\tpointer_size = {ctypes.sizeof(ctypes.c_void_p)}\n'
    
    for func in cls._functions_:
        f_name = func[0]
        args = func[1][1:]
        func_str = '@dxeapi(params={\n'
        for i in range(len(args)):
            a = args[i]
            if 'GUID' in a:
                t = 'GUID,'
            elif 'POINTER' in a:
                t = f'POINTER, #{args[i]}'
            elif '32' in a:
                t = 'UINT,'
            else:
                t = 'ULONGLONG,'
            func_str += f'\t"a{i}": {t}\n'
        func_str += '})\n'
        func_str += f'def hook_{f_name}(ctx, address, params):\n\tpass\n'
        gen_func_str += f'\t{class_instance_name}.{f_name} = ptr\n'
        gen_func_str += f'\tql.hook_address(hook_{f_name}, ptr)\n'
        gen_func_str += '\tptr += pointer_size\n'
        print(func_str, file=stram)
    gen_func_str += f'\treturn (ptr, {class_instance_name})\n'
    print(gen_func_str, file=stram)    

generate_hooks('EFI_BOOT_SERVICES', open('boot_services_hooks.py', 'w'))
generate_hooks('EFI_RUNTIME_SERVICES', open('runtime_services_hooks.py', 'w'))
