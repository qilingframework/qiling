#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, time
import cmd2
from rich import print as rprint
from ..hooks import evm_hook_insn
from .disassembler import EVMDisasm
from ..analysis.signatures import analysis_func_sign
from .utils import analysis_bytecode, bytecode_to_bytes
from .exec import EVMExecutor, debug_cmd_history
from .dbgcui import *


class EVMDebugger(cmd2.Cmd):
    def __init__(self, executor:EVMExecutor) -> None:
        shortcuts = cmd2.DEFAULT_SHORTCUTS
        extra_shortcuts = {
            'ct': 'continue',
            'si': 'stepinto',
            'bc': 'bytecode',
            'mem': 'memory',
            'bp': 'break',
            'ds': 'disasm',
            'cls': 'clear',
            'rr': 'refresh'
        }
        shortcuts.update(extra_shortcuts)
        super().__init__(shortcuts=shortcuts)
        self.init(executor)

    def init(self, executor):
        self.executor:EVMExecutor = executor
        self.executor.is_debug = True
        self.bp_list = []

        load_bytecode, runtime_code, aux_data, constructor_args = analysis_bytecode(self.executor.vm_context.msg.code)

        insns = EVMDisasm().disasm(bytecode_to_bytes(runtime_code), evm_hook_insn)
        self.func_sign = analysis_func_sign(insns, engine_num=2)

        self.cli_output()

    # override
    def _cmdloop(self) -> None:
        """Repeatedly issue a prompt, accept input, parse an initial prefix
        off the received input, and dispatch to action methods, passing them
        the remainder of the line as argument.

        This serves the same role as cmd.cmdloop().
        """
        saved_readline_settings = None

        try:
            # Get sigint protection while we set up readline for cmd2
            with self.sigint_protection:
                saved_readline_settings = self._set_up_cmd2_readline()

            # Run startup commands
            stop = self.runcmds_plus_hooks(self._startup_commands)
            self._startup_commands.clear()

            while not stop:
                # Get commands from user
                try:
                    if debug_cmd_history and debug_cmd_history[-1].startswith(('ct ', 'continue ')) and self.executor.vm_context.msg.depth != 0:
                        line = debug_cmd_history[-1]
                    else:
                        line = self._read_command_line(self.prompt)
                        debug_cmd_history.append(str(line))
                except KeyboardInterrupt:
                    self.poutput('^C')
                    line = ''

                # Run the command along with all associated pre and post hooks
                stop = self.onecmd_plus_hooks(line)
        finally:
            # Get sigint protection while we restore readline settings
            with self.sigint_protection:
                if saved_readline_settings is not None:
                    self._restore_readline(saved_readline_settings)

    # Cmd UI
    def cli_output(self):
        rprint(main_output(self))

    
    clear_parser = cmd2.Cmd2ArgumentParser()

    @cmd2.with_argparser(clear_parser)
    def do_clear(self, opt):
        """clear screen"""
        os.system('cls' if os.name == 'nt' else 'clear')


    continue_parser = cmd2.Cmd2ArgumentParser()
    continue_parser.add_argument('-sleep', type=float)

    @cmd2.with_argparser(continue_parser)
    def do_continue(self, opt):
        """continue execute"""
        if self.exit_code and self.executor.vm_context.msg.depth == 0:
            rprint('Smart Contract exec finished, use `quit` to exit cmd.')
        else:
            if opt.sleep:
                time.sleep(opt.sleep)            
            _, is_func_end = self.executor.execute(self.bp_list)
            if opt.sleep:
                time.sleep(opt.sleep)   
            self.cli_output()
            if is_func_end:
                self.exit_code = 1
                if self.executor.vm_context.msg.depth != 0:
                    return True                
                rprint('Smart Contract exec finished, use `quit` to exit cmd.')


    stepinto_parser = cmd2.Cmd2ArgumentParser()

    @cmd2.with_argparser(stepinto_parser)
    def do_stepinto(self, opt):
        """step into"""
        if self.exit_code:
            rprint('Smart Contract exec finished, use `quit` to exit cmd.')
        else:
            # try:
                opcode = int.from_bytes(self.executor.vm_context.code.read(1), byteorder='little')
                is_break = self.executor.execute_once(opcode)
                if is_break:
                    self.exit_code = 1
                    rprint('Smart Contract exec finished, use `quit` to exit cmd.')
                self.cli_output()
            # except:
            #     self.exit_code = 1
            #     rprint('Smart Contract exec exception, use `quit` to exit cmd.')


    break_parser = cmd2.Cmd2ArgumentParser()
    break_parser.add_argument('addr', type=str, help='address')

    @cmd2.with_argparser(break_parser)
    def do_break(self, opt):
        """set breakpoint at address"""
        if opt.addr.startswith('0x'):
            addr = int(opt.addr[2:], 16)
        else:
            addr = int(opt.addr)
        self.bp_list.append(addr)


    info_parser = cmd2.Cmd2ArgumentParser()
    info_subparsers = info_parser.add_subparsers()

    info_bytecode_parser = info_subparsers.add_parser('bytecode', help='View bytecode in MemoryView')
    info_bytecode_parser.add_argument('-addr', type=str, help='address')

    info_memory_parser = info_subparsers.add_parser('memory', help='View memory in MemoryView')
    info_memory_parser.add_argument('-addr', type=str, help='address')

    info_breakpoint_parser = info_subparsers.add_parser('breakpoint', help='View all current breakpoints')

    def tohex(self, cmds, byte):
        addr = None
        if cmds.addr:
            addr = cmds.addr
        if addr:
            rprint(hexdump(byte, start=int(addr)))
            return
        rprint(hexdump(byte))

    def info_bytecode(self, opt):
        code = ''.join(['%02X' % b for b in self.executor.vm_context.msg.code])
        self.tohex(opt, code)

    def info_memory(self, opt):
        if opt.addr:
            mem_bytes = self.executor.vm_context.memory_read_bytes(int(opt.addr), 16*8)
        else:
            mem_bytes = self.executor.vm_context.memory_read_bytes(0, 16*8)
        mem = ''.join(['%02X' % b for b in mem_bytes])
        self.tohex(opt, mem)

    def info_breakpoint(self, opt):
        i = 0
        for bp in self.bp_list:
            rprint(f'breakpoint{i}: {hex(bp)}')
            i += 1

    info_bytecode_parser.set_defaults(func=info_bytecode)
    info_memory_parser.set_defaults(func=info_memory)
    info_breakpoint_parser.set_defaults(func=info_breakpoint)

    @cmd2.with_argparser(info_parser)
    def do_info(self, args):
        """check informetion"""
        func = getattr(args, 'func', None)
        if func is not None:
            func(self, args)
        else:
            self.do_help('info')


    disasm_parser = cmd2.Cmd2ArgumentParser()
    disasm_parser.add_argument('-count', type=int, help='the number of disassembly lines')
    disasm_parser.add_argument('-frontcount', type=int, help='the number of behind disassembly lines')

    @cmd2.with_argparser(disasm_parser)
    def do_disasm(self, opt):
        num = 10
        front_num = 3
        if opt.count:
            num = opt.count
        if opt.frontcount:
            front_num = opt.frontcount
        
        pc = self.executor.vm_context.code.pc + 1
        current_insn_index = 0

        for i, k in enumerate(self.executor.disasm_dict): 
            if k >= pc:
                current_insn_index = i
                break

        begin_index = max(current_insn_index-front_num, 0)
        show_disasm_list = list(self.executor.disasm_dict.values())[begin_index:]
        index = 0

        for insn in show_disasm_list:
            if index >= num + 1:
                break
            rprint(f'[{insn.pc}] {insn.byte} {insn.mnemonic} {insn.imm_op}')
            index += 1


    auto_parser = cmd2.Cmd2ArgumentParser()
    auto_parser.add_argument('-count', type=int, help='how many times you want to auto step, default exec to the end')
    auto_parser.add_argument('-sleep', type=float, help='The number of seconds between steps')

    @cmd2.with_argparser(auto_parser)
    def do_auto(self, opt):
        sleep_time = 1
        if opt.sleep:
            sleep_time = opt.sleep
        if opt.count:
            for i in range(opt.count):
                self.onecmd('si', add_to_history=False)
                time.sleep(sleep_time)
                if self.exit_code == 1:
                    break
        else:
            while 1:
                self.onecmd('si', add_to_history=False)
                time.sleep(sleep_time)
                if self.exit_code == 1:
                    break
        
    write_parser = cmd2.Cmd2ArgumentParser()
    write_subparsers = write_parser.add_subparsers()

    write_stack_parser = write_subparsers.add_parser('stack', help='write stack data')
    write_stack_parser.add_argument('index', type=int)
    write_stack_parser.add_argument('value', type=str, help='must be hex')

    write_memory_parser = write_subparsers.add_parser('memory', help='write memory data')
    write_memory_parser.add_argument('addr', type=str, help='must be hex')
    write_memory_parser.add_argument('value', type=str, help='must be hex')

    def write_stack(self, opt):
        values = self.executor.vm_context._stack.values
        val = int(opt.value[2:], 16) if opt.value.startswith('0x') else int(opt.value, 16)
        try:
            if opt.index >= len(values):
                values.append((int, val))
            else:
                values[opt.index] = (int, val)
            self.executor.vm_context._stack.values = values
        except:
            rprint('Input Error, value must be int type')

    def write_memory(self, opt):
        addr = int(opt.addr[2:], 16) if opt.addr.startswith('0x') else int(opt.addr, 16)
        val = bytecode_to_bytes(opt.value)
        
        self.executor.vm_context.extend_memory(addr, len((val)))
        self.executor.vm_context.memory_write(addr, len(val), val)

    write_stack_parser.set_defaults(func=write_stack)
    write_memory_parser.set_defaults(func=write_memory)

    @cmd2.with_argparser(write_parser)
    def do_write(self, args):
        """write struction"""
        func = getattr(args, 'func', None)
        if func is not None:
            func(self, args)
        else:
            self.do_help('write')


    refresh_parser = cmd2.Cmd2ArgumentParser()

    @cmd2.with_argparser(refresh_parser)
    def do_refresh(self, opt):
        self.cli_output()



def run_debugger(executor):
    app = EVMDebugger(executor)
    res = app.cmdloop()
    return app.executor.vm_context
