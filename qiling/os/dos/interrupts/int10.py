#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import curses
import curses.ascii
from typing import Mapping

from qiling import Qiling

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

def get_attr(color_pairs: Mapping[int, Mapping[int, int]], char: int) -> int:
	fg = (char & 0x0f)
	bg = (char & 0xf0) >> 4

	# For blinking
	attr = color_pairs[fg][bg & 0b0111]

	if (bg & 0b1000) != 0:
		attr |= curses.A_BLINK

	return attr

def get_ch_non_blocking(scr) -> int:
	scr.timeout(0)
	key = scr.getch()
	scr.timeout(-1)

	return key

def __leaf_00(ql: Qiling):
	# time to set up curses
	# copied from curses.wrapper

	stdscr = curses.initscr()
	curses.noecho()
	curses.cbreak()
	stdscr.keypad(True)

	try:
		curses.start_color()
	except:
		pass

	al = ql.reg.al

	resolution = {
		0x00 : (25, 40),
		0x01 : (25, 40),
		0x02 : (25, 80),
		0x03 : (25, 80),
		0x04 : (200, 320),
		0x05 : (200, 320),
		0x06 : (200, 640),
		0x08 : (200, 160),
		0x09 : (200, 320),
		0x0a : (200, 640),
		0x0d : (200, 320),
		0x0e : (200, 640),
		0x0f : (350, 640),
		0x10 : (350, 640),
		0x11 : (480, 640),
		0x12 : (480, 640),
		0x13 : (200, 320)
	}.get(al)

	if resolution is None:
		ql.log.exception(f'resolution not implemented (al: {al:#02x})')
		raise NotImplementedError()

	curses.resizeterm(*resolution)

	# Quoted from https://linux.die.net/man/3/resizeterm
	#
	# If ncurses is configured to supply its own SIGWINCH handler, 
	# the resizeterm function ungetch's a KEY_RESIZE which will be 
	# read on the next call to getch.
	ch = get_ch_non_blocking(stdscr)

	if ch == curses.KEY_RESIZE:
		ql.log.info(f'terminal has been resized')
	elif ch != -1:
		curses.ungetch(ch)

	stdscr.scrollok(True)

	if not curses.has_colors():
		ql.log.warning(f'your terminal does not support colors, content might not be displayed correctly')

	# https://en.wikipedia.org/wiki/BIOS_color_attributes
	# blink support?
	if curses.has_colors():
		for fg in range(16):
			for bg in range(16):
				color_pair_index = 16 * fg + bg + 1

				if fg not in ql.os.color_pairs:
					ql.os.color_pairs[fg] = {}

				curses.init_pair(color_pair_index, COLORS_MAPPING[fg], COLORS_MAPPING[bg])
				color_pair = curses.color_pair(color_pair_index)

				ql.os.color_pairs[fg][bg] = color_pair
				ql.os.revese_color_pairs[color_pair] = (fg, bg)

	ql.os.stdscr = stdscr

def __leaf_01(ql: Qiling):
	# limited support
	ch = ql.reg.ch

	if (ch & 0x20):
		curses.curs_set(0)

def __leaf_02(ql: Qiling):
	# page number ignored
	dh = ql.reg.dh	# row
	dl = ql.reg.dl	# column

	ql.os.stdscr.move(dh, dl)

def __leaf_05(ql: Qiling):
	# No idea how to implement, do nothing here.
	ql.reg.al = 0

def __leaf_06(ql: Qiling):
	stdscr = ql.os.stdscr

	al = ql.reg.al	# lines to scroll
	ch = ql.reg.ch	# row of upper-left cornner
	cl = ql.reg.cl	# column of upper-left corner
	dh = ql.reg.dh	# row of lower right corner
	dl = ql.reg.dl	# column of lower righ corner
	bh = ql.reg.bh	# color

	y, x = stdscr.getmaxyx()
	cy, cx = stdscr.getyx()
	attr = get_attr(ql.os.color_pairs, bh)

	if ch != 0 or cl != 0 or dh != y - 1 or dl != x - 1:
		ql.log.warning(f'Partial scroll is unsupported. Will scroll the whole page.')
		ql.log.warning(f'Resolution: {y}x{x} but asked to scroll [({ch},{cl}), ({dh}, {dl})]')

	if al == 0:
		stdscr.clear()

		# Alternate way?
		#for ln in range(y):
		#    stdscr.addstr(ln, 0, " " * x, attr)

		stdscr.bkgd(" ", attr)
		stdscr.move(0, 0)

	else:
		stdscr.scroll(al)
		ny = 0

		if cy - al < 0:
			ny = 0
		else:
			ny = cy - al + 1

		if al > y:
			al = y

		for ln in range(al):
			stdscr.addstr(ny + ln, 0, " " * x, attr)

		stdscr.move(cy, cx)

def __leaf_08(ql: Qiling):
	stdscr = ql.os.stdscr

	if stdscr is None:
		ql.reg.ax = 0x0720
	else:
		cy, cx = stdscr.getyx()
		inch = stdscr.inch(cy, cx)
		attr = inch & curses.A_COLOR
		ch = inch & 0xFF
		ql.reg.al = ch
		pair_number = curses.pair_number(attr)

		fg, bg = curses.pair_content(pair_number)
		orig_fg = REVERSE_COLORS_MAPPING[fg]
		orig_bg = REVERSE_COLORS_MAPPING[bg]

		if attr & curses.A_BLINK:
			orig_bg |= 0b1000

		ql.reg.ah = ((orig_bg << 4) & orig_fg)

def __leaf_0e(ql: Qiling):
	al = ql.reg.al

	ql.log.debug(f'echo: {al:02x} -> {curses.ascii.unctrl(al)}')

	stdscr = ql.os.stdscr
	cy, cx = stdscr.getyx()

	# https://stackoverflow.com/questions/27674158/how-to-get-color-information-with-mvinch
	# https://linux.die.net/man/3/inch
	# https://github.com/mirror/ncurses/blob/master/include/curses.h.in#L1197
	# wtf curses...

	if al == 0xa:
		y, x = stdscr.getmaxyx()

		# \n will erase current line with echochar, so we have to handle it carefully.
		ql.log.info(f"Resolution: {x}x{y}, Cursor position: {cx},{cy}, Going to get a new line.")

		if (y - 1) == cy:
			# scroll doesn't affect our cursor
			stdscr.scroll(1)
			stdscr.move(cy, 0)
		else:
			stdscr.move(cy + 1, 0)
	else:
		attr = stdscr.inch(cy, cx) & curses.A_COLOR

		stdscr.echochar(al, attr)


# BIOS video support
# https://en.wikipedia.org/wiki/INT_10H
# https://stanislavs.org/helppc/idx_interrupt.html
# implemented by curses
def handler(ql: Qiling):
	ah = ql.reg.ah

	leaffunc = {
		0x00 : __leaf_00,
		0x01 : __leaf_01,
		0x02 : __leaf_02,
		0x05 : __leaf_05,
		0x06 : __leaf_06,
		0x08 : __leaf_08,
		0x0e : __leaf_0e
	}.get(ah)

	if leaffunc is None:
		ql.log.exception(f'leaf {ah:02x}h of INT 10h is not implemented')
		raise NotImplementedError()

	leaffunc(ql)

	if ql.os.stdscr is not None:
		ql.os.stdscr.refresh()
