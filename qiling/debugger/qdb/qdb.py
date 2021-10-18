#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Callable, Optional, Mapping, Tuple

import cmd

from qiling import Qiling
from qiling.const import QL_ARCH, QL_VERBOSE
from qiling.debugger import QlDebugger

from .frontend import context_reg, context_asm, examine_mem
from .utils import parse_int, handle_bnj, is_thumb, CODE_END
from .utils import Breakpoint, TempBreakpoint
from .const import *


class QlQdb(cmd.Cmd, QlDebugger):

    def __init__(self: QlQdb, ql: Qiling, init_hook: str = "", rr: bool = False) -> None:

        self._ql = ql
        self.prompt = "(Qdb) "
        self.breakpoints = {}
        self._saved_reg_dump = None
        self.bp_list = {}
        self.rr = rr

        if self.rr:
            self._states_list = []

        super().__init__()

        # setup a breakpoint at entry point or user specified address
        address = self._ql.loader.entry_point if not init_hook else parse_int(init_hook)
        self.set_breakpoint(address, is_temp=True)
        self.dbg_hook()

    def dbg_hook(self: QlQdb):
        """
        hook every instruction with callback funtion _bp_handler
        """

        self._ql.hook_code(self._bp_handler)

    @property
    def cur_addr(self: QlQdb) -> int:
        """
        getter for current address of qiling instance
        """

        return self._ql.reg.arch_pc

    @cur_addr.setter
    def cur_addr(self: QlQdb, address: int) -> None:
        """
        setter for current address of qiling instance
        """

        self._ql.reg.arch_pc = address

    def _bp_handler(self: QlQdb, *args) -> None:
        """
        internal function for handling once breakpoint hitted
        """

        if (bp := self.bp_list.get(self.cur_addr, None)) is not None:

            if not isinstance(bp, TempBreakpoint):
                print(f"{color.CYAN}[+] hit breakpoint at 0x{self.cur_addr:08x}{color.END}")

            else:
                # remove TempBreakpoint once hitted
                self.del_breakpoint(self.cur_addr)

            self.interactive()

    def _save(self: QlQdb, *args) -> None:
        """
        internal function for saving state of qiling instance
        """

        self._states_list.append(self._ql.save())

    def _restore(self: QlQdb, *args) -> None:
        """
        internal function for restoring state of qiling instance
        """

        self._ql.restore(self._states_list.pop())

    def _run(self: Qldbg, *args) -> None:
        """
        internal function for launching qiling instance
        """

        self._ql.run()

    def parseline(self: QlQdb, line: str) -> Tuple[Optional[str], Optional[str], str]:
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

    def interactive(self: QlQdb, *args) -> None:
        """
        initial an interactive interface
        """

        self.do_context()

        return self.cmdloop()

    def run(self: QlQdb, *args) -> None:
        """
        do nothing, since it's already running when breakpoint hitted
        """

        pass

    def emptyline(self: QlQdb, *args) -> None:
        """
        repeat last command
        """

        if (lastcmd := getattr(self, "do_" + self.lastcmd, None)):
            return lastcmd()

    def do_run(self: QlQdb, *args) -> None:
        """
        launch qiling instance from a fresh start
        """

        self._ql = Qiling(
                argv=self._ql.argv,
                rootfs=self._ql.rootfs,
                verbose=self._ql.verbose,
                console=self._ql.console,
                log_file=self._ql.log_file,
            )

        self.dbg_hook()
        self._run()

    def do_context(self: QlQdb, *args) -> None:
        """
        show context information for current location
        """

        context_reg(self._ql, self._saved_reg_dump)
        context_asm(self._ql, self.cur_addr)

    def do_backward(self: QlQdb, *args) -> None:
        """
        step barkward if it's possible, option rr should be enabled and previous instruction must be executed before
        """

        if getattr(self, "_states_list", None) is None or len(self._states_list) == 0:
            print(f"{color.RED}[!] there is no way back !!!{color.END}")

        else:
            print(f"{color.CYAN}[+] step backward ~{color.END}")
            self._restore()
            self.do_context()

    def do_step(self: QlQdb, *args) -> Optional[bool, None]:
        """
        execute one instruction at a time
        """

        if self._ql is None:
            print(f"{color.RED}[!] The program is not being run.{color.END}")

        else:
            self._saved_reg_dump = dict(filter(lambda d: isinstance(d[0], str), self._ql.reg.save().items()))

            next_stop = handle_bnj(self._ql, self.cur_addr)

            if next_stop is CODE_END:
                return True

            self.bp_list.update({next_stop: TempBreakpoint()})

            if self.rr:
                self._save()

            return True

    def set_breakpoint(self: QlQdb, address: int, is_temp: bool = False) -> None:
        """
        internal function for placing breakpoints
        """

        bp = TempBreakpoint() if is_temp else Breakpoint()

        self.bp_list.update({address: bp})

    def del_breakpoint(self: QlQdb, address: int) -> None:
        """
        internal function for removing breakpoints
        """

        self.bp_list.pop(address, None)

    def do_start(self: QlQdb, address: str = "", *args) -> None:
        """
        pause at entry point by setting a temporary breakpoint on it
        """

        # entry = self._ql.loader.entry_point  # ld.so
        # entry = self._ql.loader.elf_entry # .text of binary

        self._run()

    def do_breakpoint(self: QlQdb, address: str = "") -> None:
        """
        set breakpoint on specific address
        """

        # address = parse_int(address) if address else self._ql.reg.arch_pc
        address = parse_int(address) if address else self.cur_addr

        self.set_breakpoint(address)

        print(f"{color.CYAN}[+] Breakpoint at 0x{address:08x}{color.END}")

    def do_continue(self: QlQdb, address: str = "") -> None:
        """
        continue execution from current address if no specified 
        """

        if address:
            self.cur_addr = parse_int(address)

        print(f"{color.CYAN}continued from 0x{self.cur_addr:08x}{color.END}")
        return True

    def do_examine(self: QlQdb, line: str) -> None:
        """
        Examine memory: x/FMT ADDRESS.
        format letter: o(octal), x(hex), d(decimal), u(unsigned decimal), t(binary), f(float), a(address), i(instruction), c(char), s(string) and z(hex, zero padded on the left)
        size letter: b(byte), h(halfword), w(word), g(giant, 8 bytes)
        e.g. x/4wx 0x41414141 , print 4 word size begin from address 0x41414141 in hex
        """

        try:
            if not examine_mem(self._ql, line):
                self.do_help("examine")
        except:
            print(f"{color.RED}[!] something went wrong ...{color.END}")

    def do_show(self: QlQdb, *args) -> None:
        """
        show some runtime information
        """

        self._ql.mem.show_mapinfo()
        print(f"Breakpoints: {[hex(addr) for addr in self.bp_list.keys()]}")

    def do_disassemble(self: QlQdb, address: str, /, *args, **kwargs) -> None:
        """
        disassemble instructions from address specified
        """

        try:
            context_asm(self._ql, parse_int(address), 4)
        except:
            print(f"{color.RED}[!] something went wrong ...{color.END}")

    def do_shell(self: QlQdb, *command) -> None:
        """
        run python code
        """

        try:
            print(eval(*command))
        except:
            print("something went wrong ...")

    def do_quit(self: QlQdb, *args) -> bool:
        """
        exit Qdb and stop running qiling instance
        """
        # breakpoint()

        self._ql.stop()
        return True

    do_r = do_run
    do_s = do_step
    do_q = do_quit
    do_x = do_examine
    do_p = do_backward
    do_c = do_continue
    do_b = do_breakpoint
    do_dis = do_disassemble


if __name__ == "__main__":
    pass
