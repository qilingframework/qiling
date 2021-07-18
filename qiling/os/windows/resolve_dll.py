#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.const import QL_ARCH, QL_INTERCEPT
from qiling.exception import QlErrorSyscallError, QlErrorSyscallNotFound

import os
import pefile
from capstone import*
from capstone.x86 import *
from unicorn import *


def calibrate_reg_name(reg_name):
    if reg_name not in ['sil', 'dil']:
        return reg_name

    if reg_name == 'sil':
        return 'si'
    elif reg_name == 'dil':
        return 'di'

def resolve_symbol(ql: Qiling, address: int, size):
    #reg = ql.reg.save()

    # Check the address to jump is in memory map. If not, check if it needs to load additional dll.
    buf = ql.mem.read(address, size)
    if ql.archtype == QL_ARCH.X8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)   
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    
    op = list(md.disasm(buf, address))[0]
    
    jump_address = -1
    jump_pointer_address = -1
    #print("0x{:08x}".format(address), op.mnemonic, op.op_str)
    if op.mnemonic in ['jmp', 'call', 'mov']:
        if op.mnemonic in ['jmp', 'call']:
            pointer_operand = op.operands[0]
        elif op.mnemonic in ['mov']:
            pointer_operand = op.operands[1]
        
        if pointer_operand.type == X86_OP_MEM:
            #print("\t\toperands.type: MEM")
            jump_pointer_address = 0
            if pointer_operand.value.mem.base != 0:
                #print("\t\t\toperands.mem.base: REG = %s" % (op.reg_name(pointer_operand.value.mem.base)))
                reg_name = calibrate_reg_name(op.reg_name(pointer_operand.value.mem.base))
                jump_pointer_address += ql.reg.read(reg_name)
                if 'ip' in reg_name:
                    jump_pointer_address += size

            if pointer_operand.value.mem.index != 0:
                #print("\t\t\toperands.mem.index: REG = %s" % (op.reg_name(pointer_operand.value.mem.index)))
                reg_name = calibrate_reg_name(op.reg_name(pointer_operand.value.mem.index))
                jump_pointer_address += ql.reg.read(reg_name)
                if 'ip' in reg_name:
                    jump_pointer_address += size

            if pointer_operand.value.mem.disp != 0:
                #print("\t\t\toperands.mem.disp: 0x%x" % (pointer_operand.value.mem.disp))
                jump_pointer_address += pointer_operand.value.mem.disp

        #print(' pointer:{:016x}, address:{:016x}'.format(jump_pointer_address, jump_address))
        # check if library is already imported or not.
        if(is_in_executable_memory_address(ql, jump_pointer_address)):
            if ql.archtype == QL_ARCH.X8664:
                jump_address = int.from_bytes(
                    ql.mem.read(
                        jump_pointer_address, 
                        8
                    ),
                    'little'
                )   
            else:
                jump_address = int.from_bytes(
                    ql.mem.read(
                        jump_pointer_address, 
                        4
                    ),
                    'little'
                ) 


        if (not is_in_executable_memory_address(ql, jump_address)) and (jump_address != -1) and (jump_pointer_address != -1):
            #print('is_in_executable_memory_address: pointer:{:016x}, address:{:016x}'.format(jump_pointer_address, jump_address))
            load_additional_dll(ql, jump_pointer_address)

    return 

def get_base_address(ql, map_name):
    map_info = ql.mem.map_info

    for mi in map_info:
        _map_name = mi[3]
        if ('.dll' in _map_name) or ('[PE]' == _map_name):
            if _map_name == map_name:
                return mi[0]

    return None

def is_in_executable_memory_address(ql, address):
    for mi in ql.mem.map_info:
        if ('.dll' in mi[3]) or ('[PE]' == mi[3]):
            if (mi[0] < address) and (address < mi[1]):
                return True
    return False

def is_in_allocated_memory_address(ql, address):
    for mi in ql.mem.map_info:
        if (mi[0] < address) and (address < mi[1]):
            return True
    return False


def load_additional_dll(ql, import_address):
    """
    Load additional dll that is not loaded at the begining of qiling run.
    The function may be used for the dll, which is called from other dll that have been already loaded.

    Args:
        ql(obj): qiling object.
        import_address(int): external address of the function called by unloaded dll.\
    Return:
        boolean:  True if Add dll to memory successfully, otherwise False.
    """

    dll_list = {}
    #  ql.mem.map_info example: [140737221971968, 140737222746112, 7, 'kernel32.dll']
    map_info = ql.mem.map_info

    dll_last_address = 0x0

    for mi in map_info:
        dll_name = mi[3]
        if ('.dll' in dll_name) or ('[PE]' == dll_name):
            dll_list[dll_name] = {
                'dll': dll_name,
                'base': mi[0],
                'end': mi[1], 
            }
            dll_last_address = mi[1]

    #print(dll_list.keys())

    for dll_name in dll_list.keys():
        if (dll_list[dll_name]['base'] < import_address) and (import_address < dll_list[dll_name]['end']):
            target_dll_name = dll_name
            target_dll_base = dll_list[dll_name]['base']
            break
    else:
        return

    #print('Windows/system32/{}'.format(target_dll_name))

    # if dll_name == '[PE]':
    #     target_dll_bin = ql.loader.pe
    #     target_dll_image_base = target_dll_bin.OPTIONAL_HEADER.ImageBase
    # else:
    #     target_dll_bin = pefile.PE(ql.rootfs+'/Windows/system32/{}'.format(target_dll_name))
    #     target_dll_image_base = target_dll_bin.OPTIONAL_HEADER.ImageBase

    #print(target_dll_bin)
    # Sometimes pe file don't have DIRECTORY_ENTRY_IMPORT
    # if not hasattr(target_dll_bin, 'DIRECTORY_ENTRY_IMPORT'):
    #     return False
    #print(ql.loader.entry_import_table[target_dll_name].keys())

    if import_address not in ql.loader.entry_import_table[target_dll_name].keys():
        #print('not in table: {}'.format(import_address))
        return False

    entry_import = ql.loader.entry_import_table[target_dll_name][import_address]
    target_symbol, export_dll_name = entry_import['symbol'], entry_import['dll']

    #print(export_dll_name, target_symbol)

    if entry_import['dll'] not in ql.loader.import_address_table.keys():
        #print('export_dll_name: {}'.format(export_dll_name))
        # The case of API Set dll
        #  ref: https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-apisets                   
        if (export_dll_name[0:4] == 'api-') or (export_dll_name[0:4] == 'ext-'):
            export_dll_name, target_symbol = get_export_symbol_from_api_dll(ql, export_dll_name, target_symbol)

            #print('export_dll_name: {}'.format(export_dll_name))
            # export dll is not exist
            if (export_dll_name is None):
                return False

        # *Additional dll must not be loaded because import symbol is not resolved, but the case of API set dll, export_dll might be loaded.*
        if (export_dll_name not in dll_list.keys()):
            ql.loader.load_dll(export_dll_name.encode('utf-8'))



    #print('[+] import address: {:016x}, import_dll_base: {:016x}, import_dll_image_base: {:016x}'.format(import_address, import_dll_base, import_dll_image_base))
    # print('[+] memory write {:016x} -> {}'.format(
    #     import_address, 
    #     (export_symbol_list[0].address+export_dll_base).to_bytes(8,'little')))

    #print(ql.loader.import_address_table[export_dll_name][target_symbol.encode('utf-8')])

    export_dll_base = get_base_address(ql, export_dll_name)
    ql.mem.write(
        import_address, 
        (ql.loader.import_address_table[export_dll_name][target_symbol.encode('utf-8')]).to_bytes(8,'little')
    )

    # target_symbol = None
    # for entry_import in target_dll_bin.DIRECTORY_ENTRY_IMPORT:
    #     for entry_import_symbol in entry_import.imports:
    #         if (entry_import_symbol.address - target_dll_image_base + dll_list[dll_name]['base']) == import_address:
    #             target_symbol = entry_import_symbol.name.decode('utf-8')

    #             # Go to proccess of loading additional dll from import_address if the import symbol exists.
    #             export_dll_name = entry_import.dll.decode('utf-8').lower()
    #             #print('export_dll_name: {}'.format(export_dll_name))
    #             # The case of API Set dll
    #             #  ref: https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-apisets                   
    #             if (export_dll_name[0:4] == 'api-') or (export_dll_name[0:4] == 'ext-'):
    #                 export_dll_name, target_symbol = get_export_symbol_from_api_dll(ql, export_dll_name, target_symbol)

    #                 #print('export_dll_name: {}'.format(export_dll_name))
    #                 # export dll is not exist
    #                 if (export_dll_name is None):
    #                     continue

    #             # *Additional dll must not be loaded because import symbol is not resolved, but the case of API set dll, export_dll might be loaded.*
    #             if (export_dll_name not in dll_list.keys()):
    #                 ql.loader.load_dll(export_dll_name.encode('utf-8'))

    #             export_dll_bin = pefile.PE(ql.rootfs+'/Windows/system32/{}'.format(export_dll_name))
    #             export_dll_base = get_base_address(ql, export_dll_name)

    #             resolve_import_dll_address(ql, target_dll_bin, target_dll_base, export_dll_bin, export_dll_base, target_symbol, import_address)

    #             return True

    #print('no dll: ', target_dll_name)
    return False

def resolve_import_dll_address(ql, import_dll_bin, import_dll_base, export_dll_bin, export_dll_base, target_symbol, import_address):
    """
    Make IAT of import address.

    Args:
        ql(obj): qiling object.
        import_dll_name(str): Dll to import. it must be loaded already.
        export_dll_name(str): Dll to export.
    Return:
        boolean:  True if Add dll to memory successfully, otherwise False.
    """        

    #print(import_dll_base, export_dll_base, target_symbol, import_address)
    # dll_name is the dll imported by the binary
    import_dll_image_base = import_dll_bin.OPTIONAL_HEADER.ImageBase

    # split \x00 since section.Name sometime like this b'.text\x00\x00\x00' 
    rdata_section = list(filter(lambda x: x.Name.decode('utf-8').split('\x00')[0] == '.rdata', import_dll_bin.sections))

    # entry_import_dll_name is the dll described as import dll in dll_name
    if import_dll_bin.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress == 0:
        return False

    # insert if statement since sometimes DIRECTORY_ENTRY_EXPORT.symbols.name is None
    export_symbol_list = list(filter(lambda x: x.name.decode('utf-8') == target_symbol if x.name != None else False, export_dll_bin.DIRECTORY_ENTRY_EXPORT.symbols))
    if len(export_symbol_list) == 0:
        return False

    #print('[+] import address: {:016x}, import_dll_base: {:016x}, import_dll_image_base: {:016x}'.format(import_address, import_dll_base, import_dll_image_base))
    # print('[+] memory write {:016x} -> {}'.format(
    #     import_address, 
    #     (export_symbol_list[0].address+export_dll_base).to_bytes(8,'little')))

    ql.mem.write(
        import_address, 
        (export_symbol_list[0].address+export_dll_base).to_bytes(8,'little')
    )

    return True

def get_export_symbol_from_api_dll(ql, api_dll_name, target_symbol):
    def _get_string_from_pe(api_dll, target_symbol):
        offset = 0
        string = ''
        dll_base = api_dll.OPTIONAL_HEADER.ImageBase

        export_symbol_list = list(filter(lambda x: x.name.decode('utf-8') == target_symbol, api_dll.DIRECTORY_ENTRY_EXPORT.symbols))
        if len(export_symbol_list) == 0:
            return ''

        while True:
            #print(hex(export_symbol_list[0].address))
            char = api_dll.get_data(export_symbol_list[0].address+offset, 1)
            if char == b'\x00':
                break

            string += char.decode('utf-8')
            offset += 1
        return string

    #print(os.path.join(ql.rootfs, 'Windows/system32/{}'.format(api_dll_name)))
    if not os.path.exists(os.path.join(ql.rootfs, 'Windows/system32/{}'.format(api_dll_name))):
        return None, None

    api_dll = pefile.PE(os.path.join(ql.rootfs, 'Windows/system32/{}'.format(api_dll_name)))
    
    dll_name, export_symbol = _get_string_from_pe(api_dll, target_symbol).split('.')

    #print(dll_name, export_symbol)

    return dll_name+'.dll', export_symbol





if __name__ == "__main__":
    ql = Qiling(["../examples/rootfs/x8664_windows/bin/api_set_dll_demo.exe"],
                    "../examples/rootfs/x8664_windows",
                    verbose=QL_VERBOSE.DEFAULT)
    ql.hook_code(resolve_symbol)

    ql.run()