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
    if reg_name not in ["sil", "dil"]:
        return reg_name

    if reg_name == "sil":
        return "si"
    elif reg_name == "dil":
        return "di"

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
    if op.mnemonic in ["jmp", "call", "mov"]:
        if op.mnemonic in ["jmp", "call"]:
            pointer_operand = op.operands[0]
        elif op.mnemonic in ["mov"]:
            pointer_operand = op.operands[1]
        
        if pointer_operand.type == X86_OP_MEM:
            jump_pointer_address = 0
            if pointer_operand.value.mem.base != 0:
                reg_name = calibrate_reg_name(op.reg_name(pointer_operand.value.mem.base))
                jump_pointer_address += ql.reg.read(reg_name)
                if "ip" in reg_name:
                    jump_pointer_address += size

            if pointer_operand.value.mem.index != 0:
                reg_name = calibrate_reg_name(op.reg_name(pointer_operand.value.mem.index))
                jump_pointer_address += ql.reg.read(reg_name)
                if "ip" in reg_name:
                    jump_pointer_address += size

            if pointer_operand.value.mem.disp != 0:
                jump_pointer_address += pointer_operand.value.mem.disp

        # check if library is already imported or not.
        if(is_in_executable_memory_address(ql, jump_pointer_address)):
            if ql.archtype == QL_ARCH.X8664:
                jump_address = int.from_bytes(
                    ql.mem.read(
                        jump_pointer_address, 
                        8
                    ),
                    "little"
                )   
            else:
                jump_address = int.from_bytes(
                    ql.mem.read(
                        jump_pointer_address, 
                        4
                    ),
                    "little"
                ) 


        if (not is_in_executable_memory_address(ql, jump_address)) and (jump_address != -1) and (jump_pointer_address != -1):
            load_additional_dll(ql, jump_pointer_address)

    return 

def get_base_address(ql, map_name):
    map_info = ql.mem.map_info

    for mi in map_info:
        _map_name = mi[3]
        if (".dll" in _map_name) or ("[PE]" == _map_name):
            if _map_name == map_name:
                return mi[0]

    return None

def is_in_executable_memory_address(ql, address):
    for mi in ql.mem.map_info:
        if (".dll" in mi[3]) or ("[PE]" == mi[3]):
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
    #  ql.mem.map_info example: [140737221971968, 140737222746112, 7, "kernel32.dll"]
    map_info = ql.mem.map_info

    for mi in map_info:
        dll_name = mi[3]
        if (".dll" in dll_name) or ("[PE]" == dll_name):
            dll_list[dll_name] = {
                "dll": dll_name,
                "base": mi[0],
                "end": mi[1], 
            }

    for dll_name in dll_list.keys():
        if (dll_list[dll_name]["base"] < import_address) and (import_address < dll_list[dll_name]["end"]):
            target_dll_name = dll_name
            break
    else:
        return

    if import_address not in ql.loader.entry_import_table[target_dll_name].keys():
        return False

    entry_import = ql.loader.entry_import_table[target_dll_name][import_address]
    target_symbol, export_dll_name = entry_import["symbol"], entry_import["dll"]

    if entry_import["dll"] not in ql.loader.import_address_table.keys():
        # The case of API Set dll
        #  ref: https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-apisets                   
        if (export_dll_name[0:4] == "api-") or (export_dll_name[0:4] == "ext-"):
            export_dll_name, target_symbol = get_export_symbol_from_api_dll(ql, export_dll_name, target_symbol)

            # export dll is not exist
            if (export_dll_name is None):
                return False

        # *Additional dll must not be loaded because import symbol is not resolved, but the case of API set dll, export_dll might be loaded.*
        if (export_dll_name not in dll_list.keys()):
            ql.loader.load_dll(export_dll_name.encode("utf-8"))

    ql.mem.write(
        import_address, 
        (ql.loader.import_address_table[export_dll_name][target_symbol.encode("utf-8")]).to_bytes(8,"little")
    )

    return True


api_dll_list = {}

def get_export_symbol_from_api_dll(ql, api_dll_name, target_symbol):
    global api_dll_list

    def _get_string_from_pe(api_dll, target_symbol):
        offset = 0
        string = ""

        export_symbol_list = list(filter(lambda x: x.name.decode("utf-8") == target_symbol, api_dll.DIRECTORY_ENTRY_EXPORT.symbols))
        if len(export_symbol_list) == 0:
            return ""

        while True:
            char = api_dll.get_data(export_symbol_list[0].address+offset, 1)
            if char == b"\x00":
                break

            string += char.decode("utf-8")
            offset += 1
        return string

    if not os.path.exists(os.path.join(ql.rootfs, "Windows/system32/{}".format(api_dll_name))):
        return None, None

    if api_dll_name not in api_dll_list.keys():
        api_dll = pefile.PE(os.path.join(ql.rootfs, "Windows/system32/{}".format(api_dll_name)))
        api_dll_list[api_dll_name] = api_dll
    else:
        api_dll = api_dll_list[api_dll_name] 
    
    dll_name, export_symbol = _get_string_from_pe(api_dll, target_symbol).split(".")

    return dll_name+".dll", export_symbol





if __name__ == "__main__":
    ql = Qiling(["../examples/rootfs/x8664_windows/bin/api_set_dll_demo.exe"],
                    "../examples/rootfs/x8664_windows",
                    verbose=QL_VERBOSE.DEFAULT)
    ql.hook_code(resolve_symbol)

    ql.run()