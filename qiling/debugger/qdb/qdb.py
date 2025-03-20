#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

import cmd
import sys

from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Tuple, List, Union
from contextlib import contextmanager

from qiling.const import QL_OS, QL_ARCH, QL_VERBOSE
from qiling.debugger import QlDebugger

from .const import color
from .helper import setup_command_helper
from .misc import Breakpoint, try_read_int
from .render.render import RARROW
from .utils import setup_context_render, setup_branch_predictor, Marker, SnapshotManager, QDB_MSG, qdb_print


if TYPE_CHECKING:
    from qiling import Qiling


def save_regs(func: Callable) -> Callable[..., None]:
    """Save registers before running a certain functionality so we can display
    the registers diff.
    """

    def inner(self: 'QlQdb', *args, **kwargs) -> None:
        self.render.prev_regs = self.render.get_regs()

        func(self, *args, **kwargs)

    return inner

def liveness_check(func: Callable) -> Callable[..., None]:
    """Decorator for checking whether the program is alive.
    """

    def inner(self: 'QlQdb', *args, **kwargs) -> None:
        if self.ql is None:
            qdb_print(QDB_MSG.ERROR, 'no active emulation')
            return

        if self.predictor.has_ended():
            qdb_print(QDB_MSG.ERROR, 'the program has ended')
            return

        # proceed to functionality
        func(self, *args, **kwargs)

    return inner


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
        self.prompt = f"{color.RED}(qdb) {color.RESET}"
        self._script = script
        self.last_addr: int = -1
        self.bp_list: Dict[int, Breakpoint] = {}
        self.marker = Marker()

        self.rr = SnapshotManager(ql) if rr else None
        self.helper = setup_command_helper(ql)
        self.predictor = setup_branch_predictor(ql)
        self.render = setup_context_render(ql, self.predictor)

        super().__init__()

        # filter out entry_point of loader if presented
        self.dbg_hook(list(filter(lambda d: int(d, 0) != self.ql.loader.entry_point, init_hook)))

    def run_qdb_script(self, filename: str) -> None:
        with open(filename, 'r', encoding='latin') as fd:
            for line in fd.readlines():
                command, arg, _ = self.parseline(line)

                if command is None:
                    continue

                func = getattr(self, f"do_{command}")

                if arg:
                    func(arg)
                else:
                    func()

    def dbg_hook(self, init_hook: List[str]):
        """
        initial hook to prepare everything we need
        """

        def __bp_handler(ql: Qiling, address: int, size: int):
            if (address in self.bp_list) and (address != self.last_addr):
                bp = self.bp_list[address]

                if bp.enabled:
                    if bp.temp:
                        # temp breakpoint: remove once hit
                        self.del_breakpoint(bp)

                    else:
                        qdb_print(QDB_MSG.INFO, f'hit breakpoint at {self.cur_addr:#x}')

                    # flush unicorn translation block to avoid resuming execution from next
                    # basic block
                    self.ql.arch.uc.ctl_flush_tb()

                    ql.stop()
                    self.do_context()

            # this is used to prevent breakpoints be hit more than once in a row. without
            # it we would not be able to proceed after hitting a breakpoint
            self.last_addr = address

        self.ql.hook_code(__bp_handler)

        if self.ql.entry_point:
            self.cur_addr = self.ql.entry_point
        else:
            self.cur_addr = self.ql.loader.entry_point

        self.init_state = self.ql.save()

        # the interpreter has to be emulated, but this is not interesting for most of the users.
        # here we start emulating from interpreter's entry point while making sure the emulator
        # stops once it reaches the program entry point
        entry = getattr(self.ql.loader, 'elf_entry', self.ql.loader.entry_point) & ~0b1
        self.set_breakpoint(entry, is_temp=True)

        # init os for integrity of hooks and patches while temporarily suppress logging to let it
        # fast-forward
        with self.__set_temp(self.ql, 'verbose', QL_VERBOSE.DISABLED):
            self.ql.os.run()

        if self.ql.os.type is QL_OS.BLOB:
            self.ql.loader.entry_point = self.ql.loader.load_address

        elif init_hook:
            for each_hook in init_hook:
                self.do_breakpoint(each_hook)

        if self._script:
            self.run_qdb_script(self._script)
        else:
            self.interactive()

    @property
    def cur_addr(self) -> int:
        """Get emulation's current program counter.
        """

        return self.ql.arch.regs.arch_pc

    @cur_addr.setter
    def cur_addr(self, address: int) -> None:
        """Set emulation's current program counter.
        """

        self.ql.arch.regs.arch_pc = address

    def _run(self, address: int = 0, end: int = 0, count: int = 0) -> None:
        """Internal method for advancing emulation on different circumstences.
        """

        if not address:
            address = self.cur_addr

        if getattr(self.ql.arch, 'is_thumb', False):
            address |= 0b1

        self.ql.emu_start(begin=address, end=end, count=count)

    @contextmanager
    def save(self):
        """
        helper function for fetching specific context by emulating instructions
        """
        saved_states = self.ql.save(reg=True, mem=False)
        yield self
        self.ql.restore(saved_states)

    def parseline(self, line: str) -> Tuple[Optional[str], Optional[str], str]:
        """
        Parse the line into a command name and a string containing
        the arguments.  Returns a tuple containing (command, args, line).
        'command' and 'args' may be None if the line couldn't be parsed.
        """

        # remove potential leading or trailing spaces
        line = line.strip()

        # skip commented and empty lines
        if not line or line.startswith("#"):
            return None, None, line

        elif line.startswith('?'):
            line = 'help ' + line[1:]

        elif line.startswith('!'):
            if hasattr(self, 'do_shell'):
                line = 'shell ' + line[1:]
            else:
                return None, None, line

        i = 0
        while i < len(line) and line[i] in self.identchars:
            i += 1

        return line[:i], line[i:], line

    def interactive(self) -> None:
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

        if self.lastcmd:
            command, *arguments = self.lastcmd.split()

            lastcmd = getattr(self, f'do_{command}', None)

            if lastcmd:
                lastcmd(*arguments)

    def do_run(self, *args: str) -> None:
        """
        launch qiling instance
        """

        self._run()

    @SnapshotManager.snapshot
    @save_regs
    @liveness_check
    def do_step_in(self, *args: str) -> None:
        """Go to next instruction, stepping into function calls.
        """

        steps, *_ = args or ('',)
        steps = try_read_int(steps)

        if steps is None:
            steps = 1

        qdb_print(QDB_MSG.INFO, f'stepping {steps} steps from {self.cur_addr:#x}')

        # make sure to include delay slot when branching in mips
        if self.ql.arch.type is QL_ARCH.MIPS:
            prophecy = self.predictor.predict()

            if prophecy.going:
                steps += 1

        self._run(count=steps)
        self.do_context()

    @SnapshotManager.snapshot
    @save_regs
    @liveness_check
    def do_step_over(self, *args: str) -> None:
        """Go to next instruction, stepping over function calls.
        """

        addr, size, _, _ = self.predictor.disasm_lite(self.cur_addr)
        next_insn = addr + size

        # make sure to include delay slot when branching in mips
        if self.ql.arch.type is QL_ARCH.MIPS and self.predictor.is_branch():
            next_insn += size

        self.set_breakpoint(next_insn, is_temp=True)

        self._run()

    @SnapshotManager.snapshot
    @save_regs
    @liveness_check
    def do_continue(self, *args: str) -> None:
        """Continue execution from specified address, or from current one if
        not specified.
        """

        address, *_ = args or ('',)
        address = try_read_int(address)

        if address is None:
            address = self.cur_addr

        qdb_print(QDB_MSG.INFO, f'continuing from {address:#010x}')

        self._run(address)

    def do_backward(self, *args: str) -> None:
        """Step backwards to the previous location.

        This operation requires the rr option to be enabled and having a progress
        of at least one instruction
        """

        if self.rr is None:
            qdb_print(QDB_MSG.ERROR, 'rr was not enabled')
            return

        if not self.rr.layers:
            qdb_print(QDB_MSG.ERROR, 'there are no snapshots yet')
            return

        qdb_print(QDB_MSG.INFO, 'stepping backwards')

        self.rr.restore()
        self.do_context()

        # we did not really amualte anything going backwards, so we manually
        # updating last address
        self.last_addr = self.cur_addr

    def set_breakpoint(self, address: int, is_temp: bool = False) -> None:
        """[internal] Add or update an existing breakpoint.
        """

        self.bp_list[address] = Breakpoint(address, is_temp)

    def del_breakpoint(self, bp: Union[int, Breakpoint]) -> None:
        """[internal] Remove an existing breakpoint.

        The caller is responsible to make sure the breakpoint exists.
        """

        if isinstance(bp, int):
            try:
                bp = next(b for b in self.bp_list.values() if b.addr == bp)
            except StopIteration:
                qdb_print(QDB_MSG.ERROR, f'No breakpoint number {bp}.')
                return

        del self.bp_list[bp.addr]

    def do_breakpoint(self, *args: str) -> None:
        """Set a breakpoint on a specific address, or current one if not specified.
        """

        address, *_ = args
        address = try_read_int(address)

        if address is None:
            address = self.cur_addr

        self.set_breakpoint(address)

        qdb_print(QDB_MSG.INFO, f"breakpoint set at {address:#010x}")

    def do_disassemble(self, *args: str) -> None:
        """Disassemble a few instructions starting from specified address.
        """

        address, *_ = args
        address = try_read_int(address)

        if address is None:
            address = self.cur_addr

        self.do_examine(f'x/{self.render.disasm_num * 2}i {address}')

    def do_examine(self, line: str) -> None:
        """Examine memory.

        Usage: x/nfu target (all arguments are optional)
        Where:
            n - number of units to read
            f - format specifier
            u - unit type
        """

        try:
            self.helper.handle_examine(line)
        except (KeyError, ValueError, SyntaxError) as ex:
            qdb_print(QDB_MSG.ERROR, ex)

    def do_set(self, line: str) -> None:
        """
        set register value of current context
        """
        # set $a = b

        try:
            reg, value = self.helper.handle_set(line)
        except (KeyError, ValueError, SyntaxError) as ex:
            qdb_print(QDB_MSG.ERROR, ex)
        else:
            qdb_print(QDB_MSG.INFO, f"{reg} set to {value:#010x}")

    def do_start(self, *args: str) -> None:
        """
        restore qiling instance context to initial state
        """

        if self.ql.arch.type is QL_ARCH.CORTEX_M:
            self.ql.restore(self.init_state)
            self.do_context()

    def do_context(self, *args: str) -> None:
        """
        display context information for current location
        """

        self.render.context_reg()
        self.render.context_stack()
        self.render.context_asm()

    def do_jump(self, *args: str) -> None:
        """
        seek to where ever valid location you want
        """

        loc, *_ = args
        addr = self.marker.get_address(loc)

        if addr is None:
            addr = try_read_int(loc)

            if addr is None:
                qdb_print(QDB_MSG.ERROR, 'seek target should be a symbol or an address')
                return

        # check validation of the address to be seeked
        if not self.ql.mem.is_mapped(addr, 4):
            qdb_print(QDB_MSG.ERROR, f'seek target is unreachable: {addr:#010x}')
            return

        qdb_print(QDB_MSG.INFO, f'seeking to {addr:#010x} ...')

        self.cur_addr = addr
        self.do_context()

    def do_mark(self, *args: str):
        """
        mark a user specified address as a symbol
        """

        if not args:
            loc = self.cur_addr
            sym = self.marker.mark(loc)

        elif len(args) == 1:
            addr, *_ = args
            loc = try_read_int(addr)

            if loc is None:
                loc = self.cur_addr
                sym = args[0]

                if not self.marker.mark(loc, sym):
                    qdb_print(QDB_MSG.ERROR, f"duplicated symbol name: {sym} at address: {loc:#010x}")
                    return

            else:
                sym = self.marker.mark(loc)

        elif len(args) == 2:
            sym, addr = args
            loc = try_read_int(addr)

            if loc is None:
                qdb_print(QDB_MSG.ERROR, f"unable to mark symbol at address: '{addr}'")
                return

            else:
                self.marker.mark(loc, sym)

        else:
            qdb_print(QDB_MSG.ERROR, "symbol should not be empty ...")
            return

        qdb_print(QDB_MSG.INFO, f"mark symbol '{sym}' at address: 0x{loc:08x} ...")

    @staticmethod
    @contextmanager
    def __set_temp(obj: object, member: str, value: Any):
        """A utility context manager that temporarily sets a new value to an
        object member, only to run a certain functionality. Then the change
        is reverted.
        """

        has_member = hasattr(obj, member)

        if has_member:
            orig = getattr(obj, member)
            setattr(obj, member, value)

        try:
            yield
        finally:
            if has_member:
                setattr(obj, member, orig)

    def do_show_args(self, *args: str):
        """
        show arguments of a function call
        default argc is 2 since we don't know the function definition
        """

        argc, *_ = args or ('',)
        argc = try_read_int(argc)

        if argc is None:
            argc = 2

        if argc > 16:
            qdb_print(QDB_MSG.ERROR, 'can show up to 16 arguments')
            return

        if not self.predictor.is_fcall():
            qdb_print(QDB_MSG.ERROR, 'available only on a function call instruction')
            return

        # the cc methods were designed to access fcall arguments from within the function,
        # and therefore assume a return address is on the stack (in relevant archs), so they
        # skip it. when we are just about to call a function the return address is not yet
        # there and the arguments, if read off the stack, get messed up.
        #
        # here we work around this by temporarily cheating cc to think there is no return
        # address on the stack, so it does not skip it.

        with QlQdb.__set_temp(self.ql.os.fcall.cc, '_retaddr_on_stack', False):
            fargs = [self.ql.os.fcall.cc.getRawParam(i) for i in range(argc)]

        # mips requires a special handling since the instruction in delay slot might
        # affect one of the reg arguments values
        if self.ql.arch.type is QL_ARCH.MIPS:
            slot_addr = self.cur_addr + self.ql.arch.pointersize
            _, _, _, op_str = self.predictor.disasm_lite(slot_addr)
            operands = op_str.split(',')

            reg_args = ('$a0', '$a1', '$a2', '$a3')

            # find out whether one of the argument registers gets modified in the dealy slot
            if any(a in operands[0] for a in reg_args):
                last = self.last_addr

                dst_reg = operands[0].strip('$')
                reg_idx = int(dst_reg.strip('a'))

                # fetch real value by emulating instruction in delay slot
                with self.save() as qdb:
                    qdb._run(slot_addr, count=1)
                    real_val = self.ql.arch.regs.read(dst_reg)

                # update argument value with the calculated one
                fargs[reg_idx] = real_val

                # we don't want that to count as emulation, so restore last address
                self.last_addr = last

        nibbles = self.ql.arch.pointersize * 2

        for i, a in enumerate(fargs):
            deref = self.render.get_deref(a)

            if isinstance(deref, int):
                deref_str = f'{deref:#0{nibbles + 2}x}'

            elif isinstance(deref, str):
                deref_str = f'"{deref}"'

            else:
                deref_str = ''

            qdb_print(QDB_MSG.INFO, f'arg{i}: {a:#0{nibbles + 2}x}{f" {RARROW} {deref_str}" if deref_str else ""}')

    def do_show(self, *args: str) -> None:
        """
        show some runtime information
        """

        keyword, *_ = args or ('',)

        qdb_print(QDB_MSG.INFO, f"Entry point: {self.ql.loader.entry_point:#010x}")

        if hasattr(self.ql.loader, 'elf_entry'):
            qdb_print(QDB_MSG.INFO, f"ELF entry point: {self.ql.loader.elf_entry:#010x}")

        info_lines = iter(self.ql.mem.get_formatted_mapinfo())

        # print filed name first
        qdb_print(QDB_MSG.INFO, next(info_lines))

        # keyword filtering
        if keyword:
            lines = (line for line in info_lines if keyword in line)
        else:
            lines = info_lines

        for line in lines:
            qdb_print(QDB_MSG.INFO, line)

        qdb_print(QDB_MSG.INFO, f"Breakpoints: {[f'{addr:#010x}' for addr, bp in self.bp_list.items() if not bp.temp]}")
        qdb_print(QDB_MSG.INFO, f"Marked symbols: {[{key: f'{addr:#010x}'} for key, addr in self.marker.mark_list]}")

        if self.rr:
            qdb_print(QDB_MSG.INFO, f"Snapshots: {len(self.rr.layers)}")

    def do_script(self, filename: str) -> None:
        """
        usage: script [filename]
        load a script for automate qdb funcitonality, execute qdb command line by line basically
        """

        if filename:
            self.run_qdb_script(filename)
        else:
            qdb_print(QDB_MSG.ERROR, "parameter filename must be specified")

    def do_shell(self, *command) -> None:
        """
        run python code
        """

        # allowing arbitrary shell commands is a huge secure problem. until it gets
        # removed, block shell command in scripts for security reasons
        if self._script:
            qdb_print(QDB_MSG.ERROR, 'shell command is not allowed on script')
            return

        try:
            print(eval(*command))
        except:
            qdb_print(QDB_MSG.ERROR, "something went wrong ...")

    def do_quit(self, *args: str) -> None:
        """
        exit Qdb and stop running qiling instance
        """

        self.ql.stop()

        sys.exit(0)

    def do_EOF(self, *args: str) -> None:
        """
        handle Ctrl+D
        """

        prompt = f'{color.RED}[!] are you sure you want to quit? [Y/n]{color.END} '
        answer = input(prompt).strip()

        if not answer or answer.lower() == 'y':
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
