#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import cmd

from typing import Optional, Tuple, Union, List
from contextlib import contextmanager

from qiling import Qiling
from qiling.const import QL_OS, QL_ARCH, QL_ENDIAN, QL_STATE, QL_VERBOSE
from qiling.debugger import QlDebugger

from .utils import setup_context_render, setup_branch_predictor, setup_address_marker, SnapshotManager, run_qdb_script
from .memory import setup_memory_Manager
from .misc import parse_int, Breakpoint, TempBreakpoint, try_read_int
from .const import color

from .utils import QDB_MSG, qdb_print


class QlQdb(cmd.Cmd, QlDebugger):
    """
    The built-in debugger of Qiling Framework
    """

    def __init__(self, ql: Qiling, init_hook: List[str] = [], rr: bool = False, script: str = "") -> None:
        """
        @init_hook: the entry to be paused at
        @rr: record/replay debugging
        """

        self.ql = ql
        self.prompt = f"{color.BOLD}{color.RED}Qdb> {color.END}"
        self._saved_reg_dump = None
        self._script = script
        self.bp_list = {}
        self.marker = setup_address_marker()

        self.rr = SnapshotManager(ql) if rr else None
        self.mm = setup_memory_Manager(ql)
        self.predictor = setup_branch_predictor(ql)
        self.render = setup_context_render(ql, self.predictor)

        super().__init__()

        # filter out entry_point of loader if presented
        self.dbg_hook(list(filter(lambda d: int(d, 0) != self.ql.loader.entry_point, init_hook)))

    def dbg_hook(self, init_hook: List[str]):
        """
        initial hook to prepare everything we need
        """

        # self.ql.loader.entry_point  # ld.so
        # self.ql.loader.elf_entry    # .text of binary

        def bp_handler(ql, address, size, bp_list):

            if (bp := self.bp_list.get(address, None)):

                if isinstance(bp, TempBreakpoint):
                    # remove TempBreakpoint once hitted
                    self.del_breakpoint(bp)

                else:
                    if bp.hitted:
                        return

                    qdb_print(QDB_MSG.INFO, f"hit breakpoint at {self.cur_addr:#x}")
                    bp.hitted = True

                ql.stop()
                self.do_context()

        self.ql.hook_code(bp_handler, self.bp_list)

        if self.ql.entry_point:
            self.cur_addr = self.ql.entry_point
        else:
            self.cur_addr = self.ql.loader.entry_point

        self.init_state = self.ql.save()

        # stop emulator once interp. have been done emulating
        if addr_elf_entry := getattr(self.ql.loader, 'elf_entry', None):
            handler = self.ql.hook_address(lambda ql: ql.stop(), addr_elf_entry)
        else:
            handler = self.ql.hook_address(lambda ql: ql.stop(), self.ql.loader.entry_point)

        # suppress logging temporary
        _verbose = self.ql.verbose
        self.ql.verbose = QL_VERBOSE.DISABLED

        # init os for integrity of hooks and patches,
        self.ql.os.run()

        handler.remove()

        # ignore the memory unmap error for now, due to the MIPS memory layout issue
        try:
            self.ql.mem.unmap_all()
        except:
            pass

        self.ql.restore(self.init_state)

        # resotre logging verbose
        self.ql.verbose = _verbose

        if self.ql.os.type is QL_OS.BLOB:
            self.ql.loader.entry_point = self.ql.loader.load_address

        elif init_hook:
            for each_hook in init_hook:
                self.do_breakpoint(each_hook)

        if self._script:
            run_qdb_script(self, self._script)
        else:
            self.do_context()
            self.interactive()

    @property
    def cur_addr(self) -> int:
        """
        getter for current address of qiling instance
        """

        return self.ql.arch.regs.arch_pc

    @cur_addr.setter
    def cur_addr(self, address: int) -> None:
        """
        setter for current address of qiling instance
        """

        self.ql.arch.regs.arch_pc = address

    def _run(self, address: int = 0, end: int = 0, count: int = 0) -> None:
        """
        internal function for emulating instruction
        """

        if not address:
            address = self.cur_addr

        if getattr(self.ql.arch, 'is_thumb', False):
            address |= 0b1

        self.ql.emu_start(begin=address, end=end, count=count)

    @contextmanager
    def _save(self, reg=True, mem=True, hw=False, fd=False, cpu_context=False, os=False, loader=False):
        """
        helper function for fetching specific context by emulating instructions
        """
        saved_states = self.ql.save(reg=reg, mem=mem)
        yield self
        self.ql.restore(saved_states)

    def save_reg_dump(func) -> None:
        """
        decorator function for saving register dump
        """

        def inner(self, *args, **kwargs):
            self._saved_reg_dump = dict(filter(lambda d: isinstance(d[0], str), self.ql.arch.regs.save().items()))
            func(self, *args, **kwargs)

        return inner

    def check_ql_alive(func) -> None:
        """
        decorator function for checking ql instance is alive
        """

        def inner(self, *args, **kwargs):
            if self.ql is None:
                qdb_print(QDB_MSG.ERROR, "The program is not being run.")
            else:
                func(self, *args, **kwargs)

        return inner

    def parseline(self, line: str) -> Tuple[Optional[str], Optional[str], str]:
        """
        Parse the line into a command name and a string containing
        the arguments.  Returns a tuple containing (command, args, line).
        'command' and 'args' may be None if the line couldn't be parsed.
        """

        line = line.strip()
        if not line:
            return None, None, line
        elif line[0] == '?':
            line = 'help ' + line[1:]
        elif line.startswith('!'):
            if hasattr(self, 'do_shell'):
                line = 'shell ' + line[1:]
            else:
                return None, None, line
        i, n = 0, len(line)
        while i < n and line[i] in self.identchars: i = i+1
        cmd, arg = line[:i], line[i:].strip()
        return cmd, arg, line

    def interactive(self, *args) -> None:
        """
        initial an interactive interface
        """

        return self.cmdloop()

    def run(self, *args) -> None:
        """
        internal command for running debugger
        """

        self._run()

    def emptyline(self, *args) -> None:
        """
        repeat last command
        """

        if (lastcmd := getattr(self, "do_" + self.lastcmd, None)):
            return lastcmd()

    def do_run(self, *args) -> None:
        """
        launch qiling instance
        """

        self._run()

    @SnapshotManager.snapshot
    @save_reg_dump
    @check_ql_alive
    def do_step_in(self, step: str = '', *args) -> Optional[bool]:
        """
        execute one instruction at a time, will enter subroutine
        """
        prophecy = self.predictor.predict()

        if prophecy.where is True:
            qdb_print(QDB_MSG.INFO, 'program exited due to code end hitted')
            self.do_context()
            return False

        step = 1 if step == '' else int(step)

        # make sure follow branching
        if prophecy.going is True and self.ql.arch.type == QL_ARCH.MIPS:
            step += 1

        self._run(count=step)
        self.do_context()

    @SnapshotManager.snapshot
    @save_reg_dump
    @check_ql_alive
    def do_step_over(self, *args) -> Optional[bool]:
        """
        execute one instruction at a time, but WON't enter subroutine
        """

        prophecy = self.predictor.predict()

        if prophecy.going:
            cur_insn = self.predictor.disasm(self.cur_addr)
            bp_addr = self.cur_addr + cur_insn.size

            if self.ql.arch.type == QL_ARCH.MIPS:
                bp_addr += cur_insn.size

            self.set_breakpoint(bp_addr, is_temp=True)

        else:
            self.set_breakpoint(prophecy.where, is_temp=True)

        self._run()

    @SnapshotManager.snapshot
    @parse_int
    def do_continue(self, address: Optional[int] = None) -> None:
        """
        continue execution from current address if not specified
        """

        if address is None:
            address = self.cur_addr

        qdb_print(QDB_MSG.INFO, f"continued from 0x{address:08x}")

        self._run(address)

    def do_backward(self, *args) -> None:
        """
        step barkward if it's possible, option rr should be enabled and previous instruction must be executed before
        """

        if self.rr:
            if len(self.rr.layers) == 0 or not isinstance(self.rr.layers[-1], self.rr.DiffedState):
                qdb_print(QDB_MSG.ERROR, "there is no way back !!!")

            else:
                qdb_print(QDB_MSG.INFO, "step backward ~")
                self.rr.restore()
                self.do_context()
        else:
            qdb_print(QDB_MSG.ERROR, f"the option rr yet been set !!!")

    def set_breakpoint(self, address: int, is_temp: bool = False) -> None:
        """
        internal function for placing breakpoint
        """

        bp = TempBreakpoint(address) if is_temp else Breakpoint(address)

        self.bp_list.update({address: bp})

    def del_breakpoint(self, bp: Union[Breakpoint, TempBreakpoint]) -> None:
        """
        internal function for removing breakpoint
        """

        self.bp_list.pop(bp.addr, None)

    @parse_int
    def do_breakpoint(self, address: Optional[int] = None) -> None:
        """
        set breakpoint on specific address
        """

        if address is None:
            address = self.cur_addr

        self.set_breakpoint(address)

        qdb_print(QDB_MSG.INFO, f"Breakpoint at 0x{address:08x}")

    @parse_int
    def do_disassemble(self, address: Optional[int] = None) -> None:
        """
        disassemble instructions from address specified
        """

        try:
            context_asm(self.ql, address)
        except:
            qdb_print(QDB_MSG.ERROR)

    def do_examine(self, line: str) -> None:

        """
        Examine memory: x/FMT ADDRESS.
        format letter: o(octal), x(hex), d(decimal), u(unsigned decimal), t(binary), f(float), a(address), i(instruction), c(char), s(string) and z(hex, zero padded on the left)
        size letter: b(byte), h(halfword), w(word), g(giant, 8 bytes)
        e.g. x/4wx 0x41414141 , print 4 word size begin from address 0x41414141 in hex
        """

        if type(err_msg := self.mm.parse(line)) is str:
            qdb_print(QDB_MSG.ERROR, err_msg)


    def do_set(self, line: str) -> None:
        """
        set register value of current context
        """
        # set $a = b

        reg, val = line.split("=")
        reg_name = reg.strip().strip("$")
        reg_val = try_read_int(val.strip())

        if reg_name in self.ql.arch.regs.save().keys():
            if reg_val is not None:
                setattr(self.ql.arch.regs, reg_name, reg_val)
                self.do_context()
                qdb_print(QDB_MSG.INFO, f"set register {reg_name} to 0x{(reg_val & 0xfffffff):08x}")

            else:
                qdb_print(QDB_MSG.ERROR, f"error parsing input: {reg_val} as integer value")

        else:
            qdb_print(QDB_MSG.ERROR, f"invalid register: {reg_name}")

    def do_start(self, *args) -> None:
        """
        restore qiling instance context to initial state
        """

        if self.ql.arch != QL_ARCH.CORTEX_M:
            self.ql.restore(self.init_state)
            self.do_context()

    def do_context(self, *args) -> None:
        """
        display context information for current location
        """

        self.render.context_reg(self._saved_reg_dump)
        self.render.context_stack()
        self.render.context_asm()

    def do_jump(self, loc: str, *args) -> None:
        """
        seek to where ever valid location you want
        """

        sym = self.marker.get_symbol(loc)
        addr = sym if sym is not None else try_read_int(loc)

        # check validation of the address to be seeked
        if self.ql.mem.is_mapped(addr, 4):
            if sym:
                qdb_print(QDB_MSG.INFO, f"seek to {loc} @ 0x{addr:08x} ...")
            else:
                qdb_print(QDB_MSG.INFO, f"seek to 0x{addr:08x} ...")

            self.cur_addr = addr
            self.do_context()

        else:
            qdb_print(QDB_MSG.ERROR, f"the address to be seeked isn't mapped")

    def do_mark(self, args=""):
        """
        mark a user specified address as a symbol
        """

        args = args.split()
        if len(args) == 0:
            loc = self.cur_addr
            sym_name = self.marker.mark_only_loc(loc)

        elif len(args) == 1:
            if (loc := try_read_int(args[0])):
                sym_name = self.marker.mark_only_loc(loc)

            else:
                loc = self.cur_addr
                sym_name = args[0]
                if (err := self.marker.mark(sym_name, loc)):
                    qdb_print(QDB_MSG.ERROR, err)
                    return

        elif len(args) == 2:
            sym_name, addr = args
            if (loc := try_read_int(addr)):
                self.marker.mark(sym_name, loc)
            else:
                qdb_print(QDB_MSG.ERROR, f"unable to mark symbol at address: '{addr}'")
                return
        else:
            qdb_print(QDB_MSG.ERROR, "symbol should not be empty ...")
            return

        qdb_print(QDB_MSG.INFO, f"mark symbol '{sym_name}' at address: 0x{loc:08x} ...")

    @parse_int
    def do_show_args(self, argc: int = -1):
        """
        show arguments of a function call
        default argc is 2 since we don't know the function definition
        """

        if argc is None:
            argc = -1

        elif argc > 16:
            qdb_print(QDB_MSG.ERROR, 'Maximum argc is 16.')
            return

        prophecy = self.predictor.predict()
        if not prophecy.going:
            qdb_print(QDB_MSG.ERROR, 'Not on a braching instruction currently.')
            return

        if argc == -1:
            reg_n, stk_n = 2, 0
        else:
            if argc > 4:
                reg_n, stk_n = 4, argc - 4
            elif argc <= 4:
                reg_n, stk_n = argc, 0

        ptr_size = self.ql.arch.pointersize

        reg_args = []
        arch_type = self.ql.arch.type
        if arch_type in (QL_ARCH.MIPS, QL_ARCH.ARM, QL_ARCH.CORTEX_M, QL_ARCH.X8664):

            reg_idx = None
            if arch_type == QL_ARCH.MIPS:
                slot_addr = self.cur_addr + ptr_size

                op_str = self.predictor.disasm(slot_addr).op_str
                # register may be changed due to dealy slot
                if '$a' in op_str.split(',')[0]:
                    dst_reg = op_str.split(',')[0].strip('$')
                    reg_idx = int(dst_reg.strip('a'))

                    # fetch real value by emulating instruction in delay slot
                    with self._save() as qdb:
                        qdb._run(slot_addr, 0, count=1)
                        real_val = self.ql.arch.regs.read(dst_reg)

                reg_names = [f'a{d}'for d in range(reg_n)]
                if reg_idx != None:
                    reg_names.pop(reg_idx)

            elif arch_type in (QL_ARCH.ARM, QL_ARCH.CORTEX_M):
                reg_names = [f'r{d}'for d in range(reg_n)]

            elif arch_type == QL_ARCH.X8664:
                reg_names = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')[:reg_n]

            reg_args = [self.ql.arch.regs.read(reg_name) for reg_name in reg_names]
            if reg_idx != None:
                reg_args.insert(reg_idx, real_val)

            reg_args = list(map(hex, reg_args))

        elif arch_type == QL_ARCH.X86:
            stk_n = 2 if argc == -1 else argc

        # read arguments on stack
        if stk_n >= 0:
            shadow_n = 0
            base_offset = self.ql.arch.regs.arch_sp

            if arch_type in (QL_ARCH.X86, QL_ARCH.X8664):
                # shadow 1 pointer size for return address
                shadow_n = 1

            elif arch_type == QL_ARCH.MIPS:
                # shadow 4 pointer size for mips
                shadow_n = 4

            base_offset = self.ql.arch.regs.arch_sp + shadow_n * ptr_size
            stk_args = [self.ql.mem.read(base_offset+offset*ptr_size, ptr_size) for offset in range(stk_n)]
            endian = 'little' if self.ql.arch.endian == QL_ENDIAN.EL else 'big'
            stk_args = list(map(hex, map(lambda x: int.from_bytes(x, endian), stk_args)))

        args = reg_args + stk_args
        qdb_print(QDB_MSG.INFO, f'args: {args}')

    def do_show(self, keyword: Optional[str] = None, *args) -> None:
        """
        show some runtime information
        """

        qdb_print(QDB_MSG.INFO, f"Entry point: {self.ql.loader.entry_point:#x}")

        if addr_elf_entry := getattr(self.ql.loader, 'elf_entry', None):
            qdb_print(QDB_MSG.INFO, f"ELF entry: {addr_elf_entry:#x}")

        info_lines = iter(self.ql.mem.get_formatted_mapinfo())

        # print filed name first
        qdb_print(QDB_MSG.INFO, next(info_lines))

        # keyword filtering
        if keyword:
            lines = filter(lambda line: keyword in line, info_lines)
        else:
            lines = info_lines

        for line in lines:
            qdb_print(QDB_MSG.INFO, line)

        qdb_print(QDB_MSG.INFO, f"Breakpoints: {[hex(addr) for addr in self.bp_list.keys()]}")
        qdb_print(QDB_MSG.INFO, f"Marked symbol: {[{key:hex(val)} for key,val in self.marker.mark_list]}")
        if self.rr:
            qdb_print(QDB_MSG.INFO, f"Snapshots: {len([st for st in self.rr.layers if isinstance(st, self.rr.DiffedState)])}")

    def do_script(self, filename: str) -> None:
        """
        usage: script [filename]
        load a script for automate qdb funcitonality, execute qdb command line by line basically
        """

        if filename:
            run_qdb_script(self, filename)
        else:
            qdb_print(QDB_MSG.ERROR, "parameter filename must be specified")

    def do_shell(self, *command) -> None:
        """
        run python code
        """

        try:
            print(eval(*command))
        except:
            qdb_print(QDB_MSG.ERROR, "something went wrong ...")

    def do_quit(self, *args) -> bool:
        """
        exit Qdb and stop running qiling instance
        """

        self.ql.stop()
        if self._script:
            return True
        exit()

    def do_EOF(self, *args) -> None:
        """
        handle Ctrl+D
        """

        if input(f"{color.RED}[!] Are you sure about saying good bye ~ ? [Y/n]{color.END} ").strip() == "Y":
            self.do_quit()

    do_r = do_run
    do_s = do_step_in
    do_n = do_step_over
    do_a = do_show_args
    do_j = do_jump
    do_m = do_mark
    do_q = do_quit
    do_x = do_examine
    do_p = do_backward
    do_c = do_continue
    do_b = do_breakpoint
    do_dis = do_disassemble


if __name__ == "__main__":
    pass
