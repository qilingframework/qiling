#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from rich import print as rprint

from qiling.const import QL_VERBOSE
from ..exceptions import Halt
from .logic.invalid import InvalidOpcode
from .computation import BaseComputation


def NO_RESULT(computation: BaseComputation) -> None:
    """
    This is a special method intended for usage as the "no precompile found" result.
    The type signature is designed to match the other precompiles.
    """
    raise Exception("This method is never intended to be executed")

class CMDHistory(list):
    pass

debug_cmd_history = CMDHistory()

class EVMExecutor:
    def __init__(self,
                 Computation:BaseComputation,
                 ) -> BaseComputation:
        self.vm_context = Computation
        self.disasm_dict = self.vm_context.disasm
        self.opcode_lookup = self.vm_context.opcodes
        self.is_debug = False

        # self.debug_cmd_history = []

    def precompile_check(self):
        # Early exit on pre-compiles
        precompile = self.vm_context.precompiles.get(self.vm_context.msg.code_address, NO_RESULT)
        if precompile is not NO_RESULT:
            precompile(self.vm_context)
            return True
        return False

    def execute_once(self, opcode:int):
        try:
            pc = self.vm_context.code.pc
            dis_insn = self.disasm_dict[pc]
            opcode_fn = self.opcode_lookup[opcode]

            if dis_insn.is_hook_code:
                for h in dis_insn.callback_list.hook_code_list:
                    h.call(self.vm_context.state.ql)
            if dis_insn.is_hook_insn:
                for h in dis_insn.callback_list.hook_insn_list:
                    h.call(self.vm_context.state.ql)
            if dis_insn.is_hook_addr:
                for h in dis_insn.callback_list.hook_addr_dict[pc]:
                    h.call(self.vm_context.state.ql)

        except KeyError:
            opcode_fn = InvalidOpcode(opcode)
        
        try:
            if dis_insn:
                # if self.is_debug:
                #     rprint(f'[{dis_insn.pc}] {hex(opcode)} {dis_insn.mnemonic} {dis_insn.imm_op}')
                if self.vm_context.state.ql.verbose == QL_VERBOSE.DEBUG:
                    self.vm_context.state.ql.log.debug(f'[{dis_insn.pc}] {hex(opcode)} {dis_insn.mnemonic} {dis_insn.imm_op}')

                    stack = []
                    stack_output = 'stack ==> '
                    
                    for i in self.vm_context._stack.values:                
                        if i[0] is bytes:
                            stack.append('0x' + i[1].hex())
                        elif i[0] is int:
                            stack.append(hex(i[1]))
                        else:
                            stack.append(i)
                    for i in stack:
                        stack_output += '\n\t\t'+i

                # if self.is_debug:
                #     rprint('    '+stack_output)
                # if self.vm_context.state.ql.verbose == QL_VERBOSE.DEBUG:
                    # self.vm_context.state.ql.log.debug
                    rprint('    '+stack_output)
        
            opcode_fn(computation=self.vm_context)
            
        except Halt:
            return True

        return False

    def execute(self, bp_list=[]) -> BaseComputation:
        is_func_end = False
        if not self.is_debug:
            if self.precompile_check():
                return self.vm_context

        for opcode in self.vm_context.code:
            pc = self.vm_context.code.pc
            is_break = self.execute_once(opcode)
            if self.is_debug:
                if pc in bp_list:
                    break
            
            if is_break:
                is_func_end = True
                break
        if self.is_debug:
            return self.vm_context, is_func_end
        return self.vm_context

    def execute_debug(self):
        self.is_debug = True
        bp_list = []

        self.precompile_check()

        while True:
            if debug_cmd_history and debug_cmd_history[-1] == 'c' and self.vm_context.msg.depth != 0:
                    cmd = 'c'
            else:
                cmd = input('[evm]> ')
                debug_cmd_history.append(cmd)

            try:
                if cmd == 'si':
                    try:
                        opcode = int.from_bytes(self.vm_context.code.read(1), byteorder='little')
                        is_break = self.execute_once(opcode)
                        if is_break:
                            break
                    except:
                        break
                elif cmd == 'c':
                    _, is_func_end = self.execute(bp_list)
                    if is_func_end:
                        return self.vm_context
                elif cmd.startswith('d'):
                    _, count = cmd.split(' ')
                    nums = int(count)
                    pc = self.vm_context.code.pc
                    res = {k: v for k,v in self.disasm_dict.items() if k >= pc}
                    index = 0
                    for k, insn in res.items():
                        if index >= nums+1:
                            break
                        rprint(f'[{insn.pc}] {insn.byte} {insn.mnemonic} {insn.imm_op}')
                        index += 1
                elif cmd == 'q':
                    # too violent
                    return self.vm_context
                elif cmd.startswith('bp'):
                    _, addr = cmd.split(' ')
                    if addr.startswith('0x'):
                        addr = int(addr[2:], 16)
                    else:
                        addr = int(addr)
                    bp_list.append(addr)
                elif cmd.startswith(('list', 'l')):
                    _, opt = cmd.split(' ')
                    if opt in ['breakpoint', 'bp']:
                        rprint(bp_list)
                elif cmd.startswith(('info', 'i')):
                    def tohex(cmds, byte):
                        addr = None
                        if len(cmds) == 3:
                            addr = cmds[-1]
                        if addr:
                            rprint(self.hexdump(byte, start=int(addr)))
                            return
                        rprint(self.hexdump(byte))

                    res = cmd.split(' ')
                    opt = res[1]
                    if opt in ['bytecode', 'bc']:
                        code = ''.join(['%02X' % b for b in self.vm_context.msg.code])
                        tohex(res, code)

                    elif opt in ['memory', 'm']:
                        if len(res) == 3:
                            mem_bytes = self.vm_context.memory_read_bytes(int(res[-1]), 16*8)
                        else:
                            mem_bytes = self.vm_context.memory_read_bytes(0, 16*8)
                        mem = ''.join(['%02X' % b for b in mem_bytes])
                        tohex(res, mem)

                else:
                    raise ValueError
            except:
                step_into = 'si:  step into'
                _continue = 'c: continue'
                bp = 'bp [pc]: set breakpoint'
                _list = 'list: \n\t\tlist bp: list all breakpoint'
                rprint(f'[evm help]> \n\t{step_into}\n\t{_continue}\n\t{bp}\n\t{_list}')
                continue


    def hexdump(self, src, length=16, sep='.', minrows=8, start=0, prevsrc=""):
        """
        @brief Return {src} in hex dump.
        """
        txt = lambda c: chr(c) if 0x20 <= c < 0x7F else "."

        result = []
        result.append('           00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |  [ --ascii--]')
        result.append('')
        rows = []

        for i in range(16):
            subSrc = src[2 * (start * 16 + i * 16):2 * (start * 16 + i * 16) + length * 2]
            hexa = ''
            text = ''
            if len(subSrc) > 0:
                for h in range(0, len(subSrc), 2):
                    if h == length:
                        hexa += ' '
                    byte = int(subSrc[h:h + 2], 16)

                    # Check if it changed from op before
                    changed = False
                    if prevsrc is not None:
                        index = 2 * (start + i) * 16 + h
                        if index + 2 > len(prevsrc):
                            changed = True
                        elif int(prevsrc[index:index + 2], 16) != byte:
                            changed = True

                    if changed:
                        hexa += "{:02x} ".format(byte)
                    else:
                        hexa += "{:02x} ".format(byte)
                    text += txt(byte)

            rows.append('{:08x}:  {:<49} | {:<16} '.format(16 * (start + i), hexa, text))
            if len(rows) == minrows:
                break
        result.extend(rows)
        return '\n'.join(result)