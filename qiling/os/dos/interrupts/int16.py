#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import curses
import curses.ascii

from qiling import Qiling

# Modified from https://programtalk.com/vs2/python/8562/pyvbox/virtualbox/library_ext/keyboard.py/
SCANCODES = {
    curses.KEY_A1:    0x01,
    ord('1'):      0x02, ord('!'): 0x02,
    ord('2'):      0x03, ord('@'): 0x03,
    ord('3'):      0x04, ord('#'): 0x04,
    ord('4'):      0x05, ord('$'): 0x05,
    ord('5'):      0x06, ord('%'): 0x06,
    ord('6'):      0x07, ord('^'): 0x07,
    ord('7'):      0x08, ord('&'): 0x07,
    ord('8'):      0x09, ord('*'): 0x09,
    ord('9'):      0x0A, ord('('): 0x0A,
    ord('0'):      0x0B, ord(')'): 0x0B,
    ord('-'):      0x0C, ord('_'): 0x0C,
    ord('='):      0x0D, ord('+'): 0x0D,
    curses.KEY_BACKSPACE:   0x0E,
    ord('\b'):     0x0E,
    ord('\t'):     0x0F,
    ord('q'):      0x10, ord('Q'): 0x10,
    ord('w'):      0x11, ord('W'): 0x11,
    ord('e'):      0x12, ord('E'): 0x12,
    ord('r'):      0x13, ord('R'): 0x13,
    ord('t'):      0x14, ord('T'): 0x14,
    ord('y'):      0x15, ord('Y'): 0x15,
    ord('u'):      0x16, ord('U'): 0x16,
    ord('i'):      0x17, ord('I'): 0x17,
    ord('o'):      0x18, ord('O'): 0x18,
    ord('p'):      0x19, ord('P'): 0x19,
    ord('['):      0x1A, ord('}'): 0x1A,
    ord(']'):      0x1B, ord('{'): 0x1B,
    curses.KEY_ENTER:  0x1C,
    ord('\r'):     0x1C,
    ord('\n'):     0x1C,
    curses.KEY_C1:   0x1D,
    ord('a'):      0x1E, ord('A'): 0x1E,
    ord('s'):      0x1F, ord('S'): 0x1F,
    ord('d'):      0x20, ord('D'): 0x20,
    ord('f'):      0x21, ord('F'): 0x21,
    ord('g'):      0x22, ord('G'): 0x22,
    ord('h'):      0x23, ord('H'): 0x23,
    ord('j'):      0x24, ord('J'): 0x24,
    ord('k'):      0x25, ord('K'): 0x25,
    ord('l'):      0x26, ord('L'): 0x26,
    ord(';'):      0x27, ord(':'): 0x27,
    ord('\''):     0x28, ord('\"'):0x28,
    ord('`'):      0x29, ord('~'): 0x29,
    #'SHIFT': [[0x2A], [0xAA]], it seems hard to support shift.
    ord('\\'):     0x2B, ord('|'): 0x2B,
    ord('z'):      0x2C, ord('Z'): 0x2C,
    ord('x'):      0x2D, ord('X'): 0x2D,
    ord('c'):      0x2E, ord('C'): 0x2E,
    ord('v'):      0x2F, ord('V'): 0x2F,
    ord('b'):      0x30, ord('B'): 0x30,
    ord('n'):      0x31, ord('N'): 0x31,
    ord('m'):      0x32, ord('M'): 0x32,
    ord(','):      0x33, ord('<'): 0x33,
    ord('.'):      0x34, ord('>'): 0x34,
    ord('/'):      0x35, ord('?'): 0x35,
    #'RSHIFT': [[0x36], [0xB6]],
    curses.KEY_PRINT:  0x37,
    #'ALT':    [[0x38], [0xB8]],
    ord(' '):      0x39,
    #'CAPS':   [[0x3A], [0xBA]],
    curses.KEY_F1:     0x3B, 
    curses.KEY_F2:     0x3C, 
    curses.KEY_F3:     0x3D, 
    curses.KEY_F4:     0x3E, 
    curses.KEY_F5:     0x3F, 
    curses.KEY_F6:     0x40, 
    curses.KEY_F7:     0x41, 
    curses.KEY_F8:     0x42, 
    curses.KEY_F9:     0x43, 
    curses.KEY_F10:    0x44, 
    curses.KEY_F11:    0x57, 
    curses.KEY_F12:    0x58, 
    #'NUM':    [[0x45], [0xC5]], 
    #'SCRL':   [[0x46], [0xC6]], 
    curses.KEY_HOME:   0x47, 
    curses.KEY_UP:     0x48, 
    curses.KEY_PPAGE:   0x49, 
    #'MINUS':  [[0x4A], [0xCA]], 
    curses.KEY_LEFT:   0x4B, 
    curses.KEY_B2: 0x4C, 
    curses.KEY_RIGHT:  0x4D, 
    #'PLUS':   [[0x4E], [0xCE]], 
    curses.KEY_END:    0x4F, 
    curses.KEY_DOWN:   0x50, 
    curses.KEY_NPAGE:   0x51, 
    curses.KEY_IC:    0x52, 
    curses.KEY_DC:    0x53,
    #'E_DIV':  [[0xE0, 0x54], [0xE0, 0xD4]], 
    #'E_ENTER':[[0xE0, 0x1C], [0xE0, 0x9C]],
    #'E_INS':  [[0xE0, 0x52], [0xE0, 0xD2]],
    #'E_DEL':  [[0xE0, 0x53], [0xE0, 0xD3]],
    #'E_HOME': [[0xE0, 0x47], [0xE0, 0xC7]], 
    #'E_END':  [[0xE0, 0x4F], [0xE0, 0xCF]], 
    #'E_PGUP': [[0xE0, 0x49], [0xE0, 0xC9]], 
    #'E_PGDN': [[0xE0, 0x51], [0xE0, 0xD1]], 
    #'E_LEFT': [[0xE0, 0x4B], [0xE0, 0xCB]], 
    #'E_RIGHT':[[0xE0, 0x4D], [0xE0, 0xCD]], 
    #'E_UP':   [[0xE0, 0x48], [0xE0, 0xC8]], 
    #'E_DOWN': [[0xE0, 0x50], [0xE0, 0xD0]], 
    #'RALT':   [[0x0C, 0x38], [0xC0, 0xB8]], 
    #'RCTRL':  [[0x0C, 0x1D], [0xC0, 0x9D]], 
    #'LWIN':   [[0xE0, 0x5B], [0xE0, 0xDB]], 
    #'RWIN':   [[0xE0, 0x5C], [0xE0, 0xDC]], 
    # No scan code for pause key released
    #'PAUSE':  [[0xE1, 0x1D, 0x45, 0xE1, 0x9D, 0xC5], []],
}

def parse_key(ky):
	# https://stackoverflow.com/questions/27200597/c-ncurses-key-backspace-not-working
	# https://stackoverflow.com/questions/44943249/detecting-key-backspace-in-ncurses

	# oh my curses...
	if ky == curses.KEY_BACKSPACE or ky == 127:
		ky = ord(b'\b')

	return ky

def get_scan_code(ch):
	return SCANCODES.get(ch, 0)

def __leaf_00(ql: Qiling):
	curses.nonl()
	key = parse_key(ql.os.stdscr.getch())
	ql.log.debug(f"Get key: {hex(key)}")
	if curses.ascii.isascii(key):
		ql.reg.al = key
	else:
		ql.reg.al = 0
	ql.reg.ah = get_scan_code(key)
	curses.nl()

def __leaf_01(ql: Qiling):
	curses.nonl()
	# set non-blocking
	ql.os.stdscr.timeout(0)
	key = parse_key(ql.os.stdscr.getch())

	if key == -1:
		ql.os.set_zf()
		ql.reg.ax = 0
	else:
		ql.log.debug(f"Has key: {hex(key)} ({curses.ascii.unctrl(key)})")
		ql.reg.al = key
		ql.reg.ah = get_scan_code(key)
		ql.os.clear_zf()
		# Buffer shouldn't be removed in this interrupt.
		curses.ungetch(key)

	ql.os.stdscr.timeout(-1)
	curses.nl()

def handler(ql: Qiling):
	ah = ql.reg.ah

	leaffunc = {
		0x00 : __leaf_00,
		0x01 : __leaf_01
	}.get(ah)

	if leaffunc is None:
		ql.log.exception(f'leaf {ah:02x}h of INT 16h is not implemented')
		raise NotImplementedError()

	leaffunc(ql)
