#!/usr/bin/env python3

import cmd
from functools import partial

from qiling import *
from qiling.const import *
from qiling.debugger import QlDebugger

from .frontend import context_printer, context_reg, context_asm, examine_mem, color
from .utils import parse_int, handle_bnj, is_thumb, diff_snapshot_save, diff_snapshot_restore, CODE_END


class QlQdb(cmd.Cmd, QlDebugger):
    def __init__(self, ql, rr=False):

        self._ql = ql
        self.prompt = "(Qdb) "
        self.breakpoints = {}
        self._saved_states = None
        if rr:
            self._states_list = [None]

        super().__init__()

        # setup a breakpoint at entry point
        self._ql.hook_address(self._attach, self._ql.loader.entry_point)

    def _attach(self, ql, *args, **kwargs):
        print(color.RED, "[+] Qdb attached", color.END, sep="")
        print(color.RED, "[!] All hooks of qiling instance will be disabled in Qdb", color.END, sep="")

        # clear all hooks
        for i in ql._addr_hook_fuc.keys():
            ql.uc.hook_del(ql._addr_hook_fuc[i])

        self.interactive()

    def interactive(self, *args):
        self.cmdloop()

    def emptyline(self, *args):
        """
        repeat last command
        """
        _lastcmd = getattr(self, "do_" + self.lastcmd, None)
        if _lastcmd:
            return _lastcmd()

    def del_breakpoint(self, address):
        """
        handle internal breakpoint removing operation
        """
        _bp = self.breakpoints.pop(address, None)
        if _bp:
            _bp["hook"].remove()

    def set_breakpoint(self, address, _is_temp=False):
        """
        handle internal breakpoint adding operation
        """
        _bp_func = partial(self._breakpoint_handler, _is_temp=_is_temp)

        _hook = self._ql.hook_address(_bp_func, address)
        self.breakpoints.update({address: {"hook": _hook, "hitted": False, "temp": _is_temp}})

        if _is_temp == False:
            print("Breakpoint at 0x%08x" % address)

    def _breakpoint_handler(self, ql, _is_temp=False):
        """
        handle all breakpoints
        """
        _cur_addr = ql.reg.arch_pc

        if _is_temp: # remove temporary breakpoint
            self.del_breakpoint(_cur_addr)
        else:
            if self.breakpoints.get(_cur_addr)["hitted"]:
                return

            print("hit breakpoint at 0x%08x" % _cur_addr)
            self.breakpoints.get(_cur_addr)["hitted"] = True

        self.do_context()
        self._ql.emu_stop()

    def do_context(self, *args):
        """
        show context information for current location
        """
        context_reg(self._ql, self._saved_states)
        context_asm(self._ql, self._ql.reg.arch_pc, 4)

    def do_run(self, *args):
        """
        launch qiling instance
        """

        entry = self._ql.loader.entry_point

        self.run(entry)

    def run(self, address=None):
        """
        handle qiling instance launching
        """

        if address is None:
            return

        # for arm thumb mode
        if self._ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB) and is_thumb(self._ql.reg.cpsr):
            address |= 1

        self._ql.emu_start(address, 0)

    def do_backward(self, *args):

        if getattr(self, "_states_list", None) is None or self._states_list[-1] is None:
            print("there is no way back !!!")
        else:
            print("step backward ~")
            current_state_dicts = self._ql.save(cpu_context=True, mem=True, reg=False, fd=False)
            self._ql.restore(diff_snapshot_restore(current_state_dicts, self._states_list.pop()))
            self.do_context()

    def do_step(self, *args):
        """
        execute one instruction at a time
        """

        if self._ql is None:
            print("The program is not being run.")

        else:
            self._saved_states = dict(filter(lambda d: isinstance(d[0], str), self._ql.reg.save().items()))

            if getattr(self, "_states_list", None) is not None:
                current_state_dicts = self._ql.save(cpu_context=True, mem=True, reg=False, fd=False)
                self._states_list.append(diff_snapshot_save(current_state_dicts, self._states_list[-1]))

            _cur_addr = self._ql.reg.arch_pc

            next_stop = handle_bnj(self._ql, _cur_addr)

            if next_stop is CODE_END:
                return True

            # whether bp placed already
            if self.breakpoints.get(next_stop, None):
                self.breakpoints.get(next_stop)["hitted"] = False

            else:
                self.set_breakpoint(next_stop, _is_temp=True)

            self.run(_cur_addr)

    def do_start(self, *args):
        """
        pause at entry point by setting a temporary breakpoint on it
        """
        entry = self._ql.loader.entry_point  # ld.so
        # entry = self._ql.loader.elf_entry # .text of binary

        if self._ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB) and entry & 1:
            entry -= 1

        self.set_breakpoint(entry, _is_temp=True)
        self.do_run()

    def do_breakpoint(self, address):
        """
        set breakpoint on specific address
        """
        if address:
            baddr = parse_int(address)
            self.set_breakpoint(baddr)

    def do_continue(self, *args):
        """
        continue execution till next breakpoint or the end
        """
        if self._ql is not None:
            _cur_addr = self._ql.reg.arch_pc
            print("continued from 0x%08x" % _cur_addr)

            self.run(_cur_addr)

    def do_examine(self, args):
        """
        read data from memory of qiling instance
        """

        _args = args.split()

        if len(_args) == 1:
            _xaddr = parse_int(_args[0])
            _count = 1

        elif len(_args) == 2:
            _xaddr, _count = _args
            _xaddr = parse_int(_xaddr)
            _count = parse_int(_count)

        else:
            print("wrong format\nUsage: x ADDRESS [SIZE]")
            return

        examine_mem(self._ql, _xaddr, _count)

    def do_context(self, *args):
        """
        show context information for current location
        """
        context_reg(self._ql, self._saved_states)
        context_asm(self._ql, self._ql.reg.arch_pc, 4)

    def do_show(self, *args):
        """
        show some runtime informations
        """
        self._ql.mem.show_mapinfo()
        print("Qdb:", [(hex(idx), val) for idx, val in self.breakpoints.items()])
        print("internal:", [(hex(idx), val) for idx, val in self._ql._addr_hook.items()])

    def do_disassemble(self, address):
        """
        disassemble instructions from address specified
        """
        context_asm(self._ql, parse_int(address), 4)

    def do_shell(self, *command):
        """
        run python code,also a space between exclamation mark and command was necessary
        """
        try:
            print(eval(*command))
        except:
            print("something went wrong")

    def do_quit(self, *args):
        """
        exit Qdb
        """
        return True

    do_r = do_run
    do_s = do_step
    do_q = do_quit
    do_x = do_examine
    do_c = do_continue
    do_b = do_breakpoint
    do_p = do_backward
    do_dis = do_disassemble
    


if __name__ == "__main__":
    pass
