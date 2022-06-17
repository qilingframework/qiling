#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Callable, Optional, Mapping, Tuple, Union

import cmd

from qiling import Qiling
from qiling.const import QL_ARCH, QL_VERBOSE
from qiling.debugger import QlDebugger

from .utils import setup_context_render, setup_branch_predictor, SnapshotManager, run_qdb_script
from .memory import setup_memory_Manager
from .misc import parse_int, Breakpoint, TempBreakpoint
from .const import color

from .utils import QDB_MSG, qdb_print

class QlQdb(cmd.Cmd, QlDebugger):
    """
    The built-in debugger of Qiling Framework
    """

    def __init__(self, ql: Qiling, init_hook: str = "", rr: bool = False, script: str = "") -> None:
        """
        @init_hook: the entry to be paused at
        @rr: record/replay debugging
        """

        self.ql = ql
        self.prompt = f"{color.BOLD}{color.RED}Qdb> {color.END}"
        self._saved_reg_dump = None
        self._script = script
        self.bp_list = {}

        self.rr = SnapshotManager(ql) if rr else None
        self.mm = setup_memory_Manager(ql)
        self.predictor = setup_branch_predictor(ql)
        self.render = setup_context_render(ql, self.predictor)

        super().__init__()

        self.dbg_hook(init_hook)

    def dbg_hook(self, init_hook: str):
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

                    qdb_print(QDB_MSG.INFO, f"hit breakpoint at 0x{self.cur_addr:08x}")
                    bp.hitted = True

                ql.stop()
                self.do_context()

        self.ql.hook_code(bp_handler, self.bp_list)

        if init_hook and self.ql.loader.entry_point != init_hook:
            self.do_breakpoint(init_hook)

        self.cur_addr = self.ql.loader.entry_point

        if self.ql.arch.type == QL_ARCH.CORTEX_M:
            self._run()

        else:
            self.init_state = self.ql.save()

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

        if self.ql.arch.type == QL_ARCH.CORTEX_M and self.ql.count != 0:

            while self.ql.count:

                if (bp := self.bp_list.pop(self.cur_addr, None)):
                    if isinstance(bp, TempBreakpoint):
                        self.del_breakpoint(bp)
                    else:
                        qdb_print(QDB_MSG.INFO, f"hit breakpoint at 0x{self.cur_addr:08x}")

                    break

                self.ql.arch.step()
                self.ql.count -= 1

            return

        if self.ql.arch.type in (QL_ARCH.ARM, QL_ARCH.CORTEX_M) and self.ql.arch.is_thumb:
            address |= 1

        self.ql.emu_start(begin=address, end=end, count=count)

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
    def do_step_in(self, *args) -> Optional[bool]:
        """
        execute one instruction at a time, will enter subroutine
        """

        prophecy = self.predictor.predict()

        if prophecy.where is True:
            return True

        if self.ql.arch == QL_ARCH.CORTEX_M:
            self.ql.arch.step()
        else:
            self._run(count=1)

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
            self.set_breakpoint(self.cur_addr + cur_insn.size, is_temp=True)

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

    def do_show(self, *args) -> None:
        """
        show some runtime information
        """

        for info_line in self.ql.mem.get_formatted_mapinfo():
            self.ql.log.info(info_line)

        qdb_print(QDB_MSG.INFO, f"Breakpoints: {[hex(addr) for addr in self.bp_list.keys()]}")
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
    do_q = do_quit
    do_x = do_examine
    do_p = do_backward
    do_c = do_continue
    do_b = do_breakpoint
    do_dis = do_disassemble


if __name__ == "__main__":
    pass
