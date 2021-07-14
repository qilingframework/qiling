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
from unicorn import *
from lark import Lark, ast_utils, Transformer, v_args


def resolve_symbol(ql: Qiling, address: int, size):
    reg = ql.reg.save()

    # Check the address to jump is in memory map. If not, check if it needs to load additional dll.
    buf = ql.mem.read(address, size)
    if ql.archtype == QL_ARCH.X8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    
    
    op = list(md.disasm(buf, address))[0]
    
    jump_address = -1
    jump_pointer_address = -1
    if op.mnemonic in ['jmp', 'call']:
        #print(op.mnemonic, op.op_str)
        parser = OpcodeParser()
        jump_pointer = parser.calculate(ql, "{} {}".format(op.mnemonic, op.op_str), size)['operand']

        if jump_pointer != None:
            if "address" in jump_pointer.keys():
                jump_address = jump_pointer['address']
            elif "pointer" in jump_pointer.keys():
                jump_pointer_address = jump_pointer['pointer']
                jump_address = jump_pointer['address']

    # check if library is already imported or not.
    if (not is_in_allocated_memory_address(ql, jump_address)) and (jump_address != -1) and (jump_pointer_address != -1):
        #print('{:016x}: _is_in_allocated_memory_address'.format(jump_pointer_address))
        load_additional_dll(ql, jump_pointer_address)


        

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
        if '.dll' in dll_name:
            dll_list[dll_name] = {
                'dll': dll_name,
                'base': mi[0],
                'end': mi[1], 
            }
            dll_last_address = mi[1]


    for dll_name in dll_list.keys():
        if (dll_list[dll_name]['base'] < import_address) and (import_address < dll_list[dll_name]['end']):
            target_dll_name = dll_name
            break
    else:
        return

    print('Windows/system32/{}'.format(target_dll_name))

    target_dll_bin = pefile.PE(ql.rootfs+'/Windows/system32/{}'.format(target_dll_name))
    target_dll_image_base = target_dll_bin.OPTIONAL_HEADER.ImageBase

    target_symbol = None
    for entry_import in target_dll_bin.DIRECTORY_ENTRY_IMPORT:
        for entry_import_symbol in entry_import.imports:
            if (entry_import_symbol.address - target_dll_image_base + dll_list[dll_name]['base']) == import_address:
                target_symbol = entry_import_symbol.name.decode('utf-8')

                # Go to proccess of loading additional dll from import_address if the import symbol exists.
                export_dll_name = entry_import.dll.decode('utf-8')

                # The case of API Set dll
                #  ref: https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-apisets                   
                if (export_dll_name[0:4] == 'api-') or (export_dll_name[0:4] == 'ext-'):
                    export_dll_name, target_symbol = get_export_symbol_from_api_dll(ql, export_dll_name, target_symbol)
                    # export dll is not exist
                    if (export_dll_name is None):
                        continue

                # *Additional dll must not be loaded because import symbol is not resolved, but the case of API set dll, export_dll might be loaded.*
                if (export_dll_name not in dll_list.keys()):
                    export_dll_bin = pefile.PE(ql.rootfs+'/Windows/system32/{}'.format(export_dll_name))
                    export_dll_base = dll_last_address

                    export_dll_bin.parse_data_directories()
                    export_dll_bin.relocate_image(export_dll_base)
                    export_dll_data = bytearray(export_dll_bin.get_memory_mapped_image())

                    export_dll_len = ql.mem.align(len(bytes(export_dll_data)), 0x1000)
                    ql.mem.map(export_dll_base, export_dll_len, info=export_dll_name)
                    ql.mem.write(export_dll_base, bytes(export_dll_data))

                resolve_import_dll_address(ql, target_dll_name, export_dll_name, target_symbol, import_address)

                return True

    return False

def resolve_import_dll_address(ql, import_dll_name, export_dll_name, target_symbol, import_address):
    """
    Make IAT of import address.

    Args:
        ql(obj): qiling object.
        import_dll_name(str): Dll to import. it must be loaded already.
        export_dll_name(str): Dll to export.
    Return:
        boolean:  True if Add dll to memory successfully, otherwise False.
    """        

    dll_list = {}
    #  ql.mem.map_info example: [140737221971968, 140737222746112, 7, 'kernel32.dll']
    map_info = ql.mem.map_info

    for mi in map_info:
        dll_name = mi[3]
        if '.dll' in dll_name:
            dll_list[dll_name] = {
                'dll': dll_name,
                'base': mi[0],
            }

    if import_dll_name not in dll_list.keys():
        return False

    # dll_name is the dll imported by the binary
    print('[+] {}'.format(import_dll_name))
    import_dll_bin = pefile.PE(os.path.join(ql.rootfs, 'Windows/system32/{}'.format(import_dll_name)))
    import_dll_base = dll_list[import_dll_name]['base']
    import_dll_image_base = import_dll_bin.OPTIONAL_HEADER.ImageBase

    # split \x00 since section.Name sometime like this b'.text\x00\x00\x00' 
    rdata_section = list(filter(lambda x: x.Name.decode('utf-8').split('\x00')[0] == '.rdata', import_dll_bin.sections))

    # entry_import_dll_name is the dll described as import dll in dll_name
    if import_dll_bin.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress == 0:
        return False

    # export dll is already loaded at _load_additional_dll.
    export_dll_bin = pefile.PE(os.path.join(ql.rootfs, 'Windows/system32/{}'.format(export_dll_name)))
    export_dll_base = dll_list[export_dll_name]['base']

    # insert if statement since sometimes DIRECTORY_ENTRY_EXPORT.symbols.name is None
    export_symbol_list = list(filter(lambda x: x.name.decode('utf-8') == target_symbol if x.name != None else False, export_dll_bin.DIRECTORY_ENTRY_EXPORT.symbols))
    if len(export_symbol_list) == 0:
        return False

    print('[+] import address: {:016x}, import_dll_base: {:016x}, import_dll_image_base: {:016x}'.format(import_address, import_dll_base, import_dll_image_base))
    print('[+] memory write {:016x} -> {}'.format(
        import_address, 
        (export_symbol_list[0].address+export_dll_base).to_bytes(8,'little')))

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
            print(hex(export_symbol_list[0].address))
            char = api_dll.get_data(export_symbol_list[0].address+offset, 1)
            if char == b'\x00':
                break

            string += char.decode('utf-8')
            offset += 1
        return string

    print(os.path.join(ql.rootfs, 'Windows/system32/{}'.format(api_dll_name)))
    if not os.path.exists(os.path.join(ql.rootfs, 'Windows/system32/{}'.format(api_dll_name))):
        return None, None

    api_dll = pefile.PE(os.path.join(ql.rootfs, 'Windows/system32/{}'.format(api_dll_name)))
    
    dll_name, export_symbol = _get_string_from_pe(api_dll, target_symbol).split('.')

    print(dll_name, export_symbol)

    return dll_name+'.dll', export_symbol


class OpcodeCalculateTransformer(Transformer):
    def __init__(self, ql, op_size):
        self.ql = ql
        self.op_size = op_size

        self.reg = self.ql.reg.save()
        self.pointer_address = []

        self.do_calculate = False
        return 

    # def start(self, args):
    #     #args example: {'opcode': 'mov', 'operand': 0}
    #     if isinstance(args[0], int):
    #         return args, self.pointer_address
    #     else:
    #         return args[0], self.pointer_address

    def start(self, args):
        # opcode only
        if len(args) == 1:
            return args[0]
        else:
            return {"opcode": args[0]["opcode"], "operand":args[1]["operand"]}

    def operand(self, args):
        return {"operand": args[0]}

    def connection(self, args):
        return args

    def element(self, args):
        return args[0]
    
    def cast(self, args):
        if args[1] == None:
            return None
            
        if args[0].value == 'byte':
            args[1]['address'] &= 0xff
        elif args[0].value == 'dword':
            args[1]['address'] &= 0xffff

        return args[1]

    def pointer(self, args):
        reg = self.ql.reg.save()
    
        # args example: [{'address': 140737488474144}]
        pointer_address = args[0]['address']

        try:
            pointer_value = int.from_bytes(
                self.ql.mem.read(
                    pointer_address, 
                    8
                ),
                "little"
            ) 
            return {"pointer": pointer_address, "address": pointer_value}
        except:
            return None
        
    def address(self, args):
        return {"address": args[0]}

    def add_op(self, args):
        return args[0] + args[1]

    def sub_op(self, args):
        return args[0] - args[1]

    def mul_op(self, args):
        return args[0] * args[1]

    def primitive(self, args):
        return args[0]

    def OPCODE(self, args):
        return {"opcode": args.value}

    def HEX(self, args):
        return int(args.value, 16)

    def NUMBER(self, args):
        return int(args.value)

    def REGISTER(self, args):
        if args.value == "rip":
            # rip is not increment, need to add opcode size
            return self.reg[args.value] + self.op_size
        else:
            return self.reg[args.value]

    def STRING(self, args):
        return args.value

class OpcodeParser():
    def __init__(self):
        parser_grammer = r"""
            start : OPCODE (operand)?

            operand : connection
                | element

            connection : element "," element
            element : cast
                    | pointer
                    | address

            cast : TYPE ( pointer | address )
            pointer : "ptr" "[" address "]"
                    | "[" address "]"

            address : (primitive | add_op | sub_op | mul_op)



            add_op : (primitive)  "+"  (primitive | add_op | sub_op | mul_op)
            sub_op : (primitive)  "-"  (primitive | add_op | sub_op | mul_op)
            mul_op : (primitive)  "*"  (primitive | add_op | sub_op | mul_op)

            primitive : REGISTER
                    | HEX
                    | NUMBER
                    | STRING

            // <uppercase>.<priority>
            OPCODE.2: /[0-9a-z]+/
            HEX.2 : /0x[0-9a-f]+/
            NUMBER.2 : /-?[0-9]+/
            TYPE.2 : /(([qd]?|xmm)word|byte)/
            REGISTER.2 : /(r|e)?ax|a(l|h)|(r|e)?bx|b(l|h)|(r|e)?cx|c(l|h)|(r|e)?dx|d(l|h)|(r|e)?bp(l)?|(r|e)?sp(l)?|(r|e)?ip(l)?|(r|e)si(l)?|(r|e)di(l)?|r8(d|w|b)?|r9(d|w|b)?|r10(d|w|b)?|r11(d|w|b)?|r12(d|w|b)?|r13(d|w|b)?|r14(d|w|b)?|r15(d|w|b)?|xmm[01]/
            STRING : /[0-9a-zA-Z._:]+/

            %ignore " "
        """
        self.parser = Lark(parser_grammer, parser="lalr", propagate_positions=True)

    def calculate(self, ql, opcode, op_size):
        self.tree = self.parser.parse(opcode)
        return OpcodeCalculateTransformer(ql, op_size).transform(self.tree)


if __name__ == "__main__":
    ql = Qiling(["../examples/rootfs/x8664_windows/bin/api_set_dll_demo.exe"],
                    "../examples/rootfs/x8664_windows",
                    verbose=QL_VERBOSE.DEFAULT)
    ql.hook_code(resolve_symbol)

    ql.run()