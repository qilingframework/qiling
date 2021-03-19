#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import curses
import curses.ascii
from enum import IntEnum
from datetime import datetime

from unicorn import UcError

from qiling import Qiling
from qiling.const import QL_INTERCEPT
from qiling.os.os import QlOs

from . import interrupts

COLORS_MAPPING = {
    0: curses.COLOR_BLACK,
    1: curses.COLOR_BLUE,
    2: curses.COLOR_GREEN,
    3: curses.COLOR_CYAN,
    4: curses.COLOR_RED,
    5: curses.COLOR_MAGENTA,
    6: 9,
    7: 7,
    8: 8,
    9: 6,
    10: 10,
    11: 14,
    12: 9,
    13: 13,
    14: curses.COLOR_YELLOW,
    15: curses.COLOR_WHITE
}

REVERSE_COLORS_MAPPING = {v : k for k, v in COLORS_MAPPING.items()}

# @see: https://en.wikipedia.org/wiki/FLAGS_register
class Flags(IntEnum):
    CF = (1 << 0)    # carry
    PF = (1 << 2)    # parity
    AF = (1 << 4)    # alignment
    ZF = (1 << 6)    # zero
    SF = (1 << 7)    # sign
    TF = (1 << 8)    # trap
    IF = (1 << 9)    # interrupt
    DF = (1 << 10)   # direction
    OF = (1 << 11)   # overflow
    IOPL = (3 << 12) # io privilege

class QlOsDos(QlOs):
    def __init__(self, ql: Qiling):
        super(QlOsDos, self).__init__(ql)

        self.ql = ql
        self.hook_syscall()
        self.handle_next = 0
        self.handles = {}
        self.color_pairs = {}
        self.revese_color_pairs = {}
        self.stdscr = None
        self.dos_ver = int(self.ql.profile.get("KERNEL", "version"), 0)

    def __del__(self):
        # resume terminal
        if self.stdscr is not None:
            self.stdscr.keypad(False)
            curses.echo()
            curses.nocbreak()
            curses.endwin()

    def set_flag_value(self, fl: Flags, val: int) -> None:
        self.ql.reg.ef = self.ql.reg.ef & (~fl) | (fl * val)

    def test_flags(self, fl):
        return self.ql.reg.ef & fl == fl

    def set_cf(self):
        self.set_flag_value(Flags.CF, 0b1)

    def clear_cf(self):
        self.set_flag_value(Flags.CF, 0b0)

    def set_zf(self):
        self.set_flag_value(Flags.ZF, 0b1)

    def clear_zf(self):
        self.set_flag_value(Flags.ZF, 0b0)

    def _get_attr(self, fg, bg):
        # For blinking
        attr = self.color_pairs[fg][(bg & 0b111)]
        if (bg & 0b1000) != 0:
            attr |= curses.A_BLINK
        return attr

    def _get_ch_non_blocking(self):
        self.stdscr.timeout(0)
        key = self.stdscr.getch()
        self.stdscr.timeout(-1)
        return key

    def int10(self):
        # BIOS video support
        # https://en.wikipedia.org/wiki/INT_10H
        # https://stanislavs.org/helppc/idx_interrupt.html
        # implemented by curses
        ah = self.ql.reg.ah
        al = self.ql.reg.al
        if ah==0:
            # time to set up curses
            # copied from curses.wrapper
            self.stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            self.stdscr.keypad(True)
            try:
                curses.start_color()
            except:
                pass
            if al == 0 or al == 1:
                curses.resizeterm(25, 40)
            elif al == 2 or al == 3:
                curses.resizeterm(25, 80)
            elif al == 4 or al == 5 or al == 9 or al == 0xD or al == 0x13:
                curses.resizeterm(200, 320)
            elif al == 6:
                curses.resizeterm(200, 640)
            elif al == 8:
                curses.resizeterm(200, 160)
            elif al == 0xA or al == 0xE:
                curses.resizeterm(200, 640)
            elif al == 0xF:
                curses.resizeterm(350, 640)
            elif al == 0x10:
                curses.resizeterm(350, 640)
            elif al == 0x11 or al == 0x12:
                curses.resizeterm(480, 640)
            else:
                self.ql.log.info("Exception: int 10h syscall Not Found, al: %s" % hex(al))
                raise NotImplementedError()
            # Quoted from https://linux.die.net/man/3/resizeterm
            #
            # If ncurses is configured to supply its own SIGWINCH handler, 
            # the resizeterm function ungetch's a KEY_RESIZE which will be 
            # read on the next call to getch.
            ch = self._get_ch_non_blocking()
            if ch == curses.KEY_RESIZE:
                self.ql.log.info(f"You term has been resized!")
            elif ch != -1:
                curses.ungetch(ch)
            self.stdscr.scrollok(True)

            if not curses.has_colors():
                self.ql.log.info(f"Warning: your terminal doesn't support colors, content might not be displayed correctly.")

            # https://en.wikipedia.org/wiki/BIOS_color_attributes
            # blink support?
            if curses.has_colors():
                for fg in range(16):
                    for bg in range(16):
                        color_pair_index = 16*fg + bg + 1
                        if fg not in self.color_pairs:
                            self.color_pairs[fg] = {}
                        curses.init_pair(color_pair_index, COLORS_MAPPING[fg], COLORS_MAPPING[bg])
                        color_pair = curses.color_pair(color_pair_index)
                        self.color_pairs[fg][bg] = color_pair
                        self.revese_color_pairs[color_pair] = (fg, bg)
        elif ah == 1:
            # limited support
            ch = self.ql.reg.ch
            if (ch & 0x20) != 0:
                curses.curs_set(0)
        elif ah == 2:
            # page number ignored
            dh = self.ql.reg.dh # row
            dl = self.ql.reg.dl # column
            self.stdscr.move(dh, dl)
        elif ah == 5:
            # No idea how to implement, do nothing here.
            self.ql.reg.al = 0
            pass
        elif ah == 6:
            al = self.ql.reg.al # lines to scroll
            ch = self.ql.reg.ch # row of upper-left cornner
            cl = self.ql.reg.cl # column of upper-left corner
            dh = self.ql.reg.dh # row of lower right corner
            dl = self.ql.reg.dl # column of lower righ corner
            bh = self.ql.reg.bh
            fg = bh & 0xF
            bg = (bh & 0xF0) >> 4
            y, x = self.stdscr.getmaxyx()
            cy, cx = self.stdscr.getyx()
            attr = self._get_attr(fg, bg)
            if ch != 0 or cl != 0 or dh != y - 1 or dl != x - 1:
                self.ql.log.info(f"Warning: Partial scroll is unsupported. Will scroll the whole page.")
                self.ql.log.info(f"Resolution: {y}x{x} but asked to scroll [({ch},{cl}),({dh}, {dl})]")
            if al != 0:
                self.stdscr.scroll(al)
                ny = 0
                if cy - al < 0:
                    ny = 0
                else:
                    ny = cy - al + 1
                if al > y:
                    al = y
                for ln in range(al):
                    self.stdscr.addstr(ny + ln, 0, " "*x, attr)
                self.stdscr.move(cy, cx)
            else:
                self.stdscr.clear()
                # Alternate way?
                #for ln in range(y):
                #    self.stdscr.addstr(ln, 0, " "*x, attr)
                self.stdscr.bkgd(" ", attr)
                self.stdscr.move(0, 0)
        elif ah == 8:
            if self.stdscr is None:
                self.ql.reg.ax = 0x0720
            else:
                cy, cx = self.stdscr.getyx()
                inch = self.stdscr.inch(cy, cx)
                attr = inch & curses.A_COLOR
                ch = inch & 0xFF
                self.ql.reg.al = ch
                pair_number = curses.pair_number(attr)
                fg, bg = curses.pair_content(pair_number)
                orig_fg = REVERSE_COLORS_MAPPING[fg]
                orig_bg = REVERSE_COLORS_MAPPING[bg]
                if attr & curses.A_BLINK != 0:
                    orig_bg |= 0b1000
                self.ql.reg.ah = ((orig_bg << 4) & orig_fg)
        elif ah == 0xE:
            self.ql.log.debug(f"Echo: {hex(al)} -> {curses.ascii.unctrl(al)}")
            y, x = self.stdscr.getmaxyx()
            cy, cx = self.stdscr.getyx()
            fg = self.ql.reg.bl
            # https://stackoverflow.com/questions/27674158/how-to-get-color-information-with-mvinch
            # https://linux.die.net/man/3/inch
            # https://github.com/mirror/ncurses/blob/master/include/curses.h.in#L1197
            # wtf curses...
            attr = self.stdscr.inch(cy, cx) & curses.A_COLOR
            if al == 0xa:
                # \n will erase current line with echochar, so we have to handle it carefully.
                self.ql.log.info(f"Resolution: {x}x{y}, Cursor position: {cx},{cy}, Going to get a new line.")
                if y-1 == cy:
                    # scroll doesn't affect our cursor
                    self.stdscr.scroll(1)
                    self.stdscr.move(cy, 0)
                else:
                    self.stdscr.move(cy+1, 0)
            else:
                self.stdscr.echochar(al, attr)
        else:
            self.ql.log.info("Exception: int 10h syscall Not Found, ah: %s" % hex(ah))
            raise NotImplementedError()
        if self.stdscr is not None:
            self.stdscr.refresh()

    def hook_syscall(self):

        # http://spike.scu.edu.au/~barry/interrupts.html
        # http://www2.ift.ulaval.ca/~marchand/ift17583/dosints.pdf
        default_api = {
            0x10: self.int10,
            0x13: lambda: interrupts.int13.handler(self.ql),
            0x15: lambda: interrupts.int15.handler(self.ql),
            0x16: lambda: interrupts.int16.handler(self.ql),
            0x19: lambda: interrupts.int19.handler(self.ql),
            0x1a: lambda: interrupts.int1a.handler(self.ql),
            0x20: lambda: interrupts.int20.handler(self.ql),
            0x21: lambda: interrupts.int21.handler(self.ql)
        }

        def cb(ql: Qiling, intno: int):
            ah = ql.reg.ah
            intinfo = (intno, ah)

            func = self.user_defined_api[QL_INTERCEPT.CALL].get(intinfo) or default_api.get(intno)
            onenter = self.user_defined_api[QL_INTERCEPT.ENTER].get(intinfo)
            onexit  = self.user_defined_api[QL_INTERCEPT.EXIT].get(intinfo)

            if onenter is not None:
                onenter(ql)

            if func is None:
                raise NotImplementedError(f'DOS interrupt {intno:02x}h is not implemented')

            ql.log.debug(f'Handling interrupt {intno:02x}h (leaf {ah:#04x})')
            func()

            if onexit is not None:
                onexit(ql)

        self.ql.hook_intr(cb)

    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        if  self.ql.entry_point is not None:
            self.ql.loader.elf_entry = self.ql.entry_point
        else:
            self.ql.entry_point = self.ql.loader.start_address

        if not self.ql.code:
            self.start_time = datetime.now()
            self.ticks_per_second = self.ql.loader.ticks_per_second

            try:
                self.ql.emu_start(self.ql.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
            except UcError:
                self.emu_error()
                raise

            if self.ql._internal_exception != None:
                raise self.ql._internal_exception 
