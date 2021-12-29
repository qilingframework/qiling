#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Callable, Optional, Mapping, Tuple, Union

import cmd

from qiling import Qiling
from qiling.const import QL_ARCH, QL_VERBOSE
from qiling.debugger import QlDebugger

from .frontend import context_reg, context_asm, examine_mem
from .utils import _parse_int, handle_bnj, is_thumb, CODE_END, parse_int
from .utils import Breakpoint, TempBreakpoint
from .const import *


class QlQdb(cmd.Cmd, QlDebugger):

    def __init__(self: QlQdb, ql: Qiling, init_hook: str = "", rr: bool = False) -> None:

        self.ql = ql
        self.prompt = f"{color.BOLD}{color.RED}Qdb> {color.END}"
        self._saved_reg_dump = None
        self.bp_list = {}
        self.rr = rr

        if self.rr:
            self._states_list = []

        super().__init__()

        self.dbg_hook(init_hook)

    def dbg_hook(self: QlQdb, init_hook: str):

        # self.ql.loader.entry_point  # ld.so
        # self.ql.loader.elf_entry    # .text of binary

        if init_hook and self.ql.loader.entry_point != init_hook:
            self.do_breakpoint(init_hook)

        self.cur_addr = self.ql.loader.entry_point

        if self.ql.archtype == QL_ARCH.CORTEX_M:
            self._run()

        else:
            self._init_state = self.ql.save()

        self.do_context()
        self.interactive()

    @property
    def cur_addr(self: QlQdb) -> int:
        """
        getter for current address of qiling instance
        """

        return self.ql.reg.arch_pc

    @cur_addr.setter
    def cur_addr(self: QlQdb, address: int) -> None:
        """
        setter for current address of qiling instance
        """

        self.ql.reg.arch_pc = address

    def _bp_handler(self: QlQdb, *args) -> None:
        """
        internal function for handling once breakpoint hitted
        """

        if (bp := self.bp_list.get(self.cur_addr, None)):

            if isinstance(bp, TempBreakpoint):
                # remove TempBreakpoint once hitted
                self.del_breakpoint(bp)

            else:
                if bp.hitted:
                    return

                print(f"{color.CYAN}[+] hit breakpoint at 0x{self.cur_addr:08x}{color.END}")
                bp.hitted = True

            self.ql.stop()
            self.do_context()

    def _save(self: QlQdb, *args) -> None:
        """
        internal function for saving state of qiling instance
        """

        self._states_list.append(self.ql.save())

    def _restore(self: QlQdb, *args) -> None:
        """
        internal function for restoring state of qiling instance
        """

        self.ql.restore(self._states_list.pop())

    def _run(self: Qldbg, address: int = 0, end: int = 0, count: int = 0) -> None:
        """
        internal function for emulating instruction
        """

        if not address:
            address = self.cur_addr

        if self.ql.archtype == QL_ARCH.CORTEX_M and self.ql.count != 0:

            while self.ql.count:

                if (bp := self.bp_list.pop(self.cur_addr, None)):
                    if isinstance(bp, TempBreakpoint):
                        self.del_breakpoint(bp)
                    else:
                        print(f"{color.CYAN}[+] hit breakpoint at 0x{self.cur_addr:08x}{color.END}")

                    break

                self.ql.arch.step()
                self.ql.count -= 1

            return

        if self.ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB, QL_ARCH.CORTEX_M) and is_thumb(self.ql.reg.cpsr):
            address |= 1

        self.ql.emu_start(begin=address, end=end, count=count)

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

        return self.cmdloop()

    def run(self: QlQdb, *args) -> None:
        """
        internal command for running debugger
        """

        self._run()

    def emptyline(self: QlQdb, *args) -> None:
        """
        repeat last command
        """

        if (lastcmd := getattr(self, "do_" + self.lastcmd, None)):
            return lastcmd()

    def do_run(self: QlQdb, *args) -> None:
        """
        launch qiling instance
        """

        self._run()

    def do_context(self: QlQdb, *args) -> None:
        """
        show context information for current location
        """

        context_reg(self.ql, self._saved_reg_dump)
        context_asm(self.ql, self.cur_addr)

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

    def do_step(self: QlQdb, *args) -> Optional[bool]:
        """
        execute one instruction at a time
        """

        if self.ql is None:
            print(f"{color.RED}[!] The program is not being run.{color.END}")

        else:
            # save reg dump for data highlighting changes
            self._saved_reg_dump = dict(filter(lambda d: isinstance(d[0], str), self.ql.reg.save().items()))

            if self.rr:
                self._save()

            _, next_stop = handle_bnj(self.ql, self.cur_addr)

            if next_stop is CODE_END:
                return True

            if self.ql.archtype == QL_ARCH.CORTEX_M:
                self.ql.arch.step()
                self.ql.count -= 1

            else:
                count = 1 if next_stop == self.cur_addr + 4 else 2
                self._run(count=count)

            self.do_context()

    def set_breakpoint(self: QlQdb, address: int, is_temp: bool = False) -> None:
        """
        internal function for placing breakpoint
        """

        bp = TempBreakpoint(address) if is_temp else Breakpoint(address)

        if self.ql.archtype != QL_ARCH.CORTEX_M:
            # skip hook_address for cortex_m
            bp.hook = self.ql.hook_address(self._bp_handler, address)

        self.bp_list.update({address: bp})

    def del_breakpoint(self: QlQdb, bp: Union[Breakpoint, TempBreakpoint]) -> None:
        """
        internal function for removing breakpoints
        """

        if self.bp_list.pop(bp.addr, None):
            bp.hook.remove()

    def do_start(self: QlQdb, *args) -> None:
        """
        restore qiling instance context to initial state
        """

        if self.ql.archtype != QL_ARCH.CORTEX_M:

            self.ql.restore(self._init_state)
            self.do_context()

    @parse_int
    def do_breakpoint(self: QlQdb, address: Optional[int] = 0) -> None:
        """
        set breakpoint on specific address
        """

        if address is None:
            address = self.cur_addr

        self.set_breakpoint(address)

        print(f"{color.CYAN}[+] Breakpoint at 0x{address:08x}{color.END}")

    @parse_int
    def do_continue(self: QlQdb, address: Optional[int] = 0) -> None:
        """
        continue execution from current address if not specified
        """

        if address is None:
            address = self.cur_addr

        print(f"{color.CYAN}continued from 0x{address:08x}{color.END}")

        self._run(address)

    def do_examine(self: QlQdb, line: str) -> None:
        """
        Examine memory: x/FMT ADDRESS.
        format letter: o(octal), x(hex), d(decimal), u(unsigned decimal), t(binary), f(float), a(address), i(instruction), c(char), s(string) and z(hex, zero padded on the left)
        size letter: b(byte), h(halfword), w(word), g(giant, 8 bytes)
        e.g. x/4wx 0x41414141 , print 4 word size begin from address 0x41414141 in hex
        """

        try:
            if not examine_mem(self.ql, line):
                self.do_help("examine")
        except:
            print(f"{color.RED}[!] something went wrong ...{color.END}")

    def do_show(self: QlQdb, *args) -> None:
        """
        show some runtime information
        """

        self.ql.mem.show_mapinfo()
        print(f"Breakpoints: {[hex(addr) for addr in self.bp_list.keys()]}")

    @parse_int
    def do_disassemble(self: QlQdb, address: Optional[int] = 0, *args) -> None:
        """
        disassemble instructions from address specified
        """

        try:
            context_asm(self.ql, _parse_int(address), self.ql.pointersize)
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

        self.ql.stop()
        exit()

    def do_EOF(self: QlQdb, *args) -> None:
        """
        handle Ctrl+D
        """
        if input(f"{color.RED}[!] Are you sure about saying good bye ~ ? [Y/n]{color.END} ").strip() == "Y":
            self.do_quit()

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
