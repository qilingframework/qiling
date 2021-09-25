#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import time

from qiling import Qiling

# @see: http://www.oldlinux.org/Linux.old/docs/interrupts/int-html/int-15.htm

def __leaf_00(ql: Qiling):
	pass

def __leaf_01(ql: Qiling):
	pass

def __leaf_53(ql: Qiling):
	al = ql.reg.al

	if al == 0x01:
		ql.os.clear_cf()
	elif al == 0x0e:
		ql.reg.ax = 0x0102
		ql.os.clear_cf()
	elif al == 0x07:
		if (ql.reg.bx == 1) and (ql.reg.cx == 3):
			ql.log.info("Emulation Stop")
			ql.emu_stop()
	else:
		raise NotImplementedError()

def __leaf_86(ql: Qiling):
	dx = ql.reg.dx
	cx = ql.reg.cx
	full_secs = ((cx << 16) + dx) / 1000000

	ql.log.info(f"Goint to sleep for {full_secs} seconds")
	time.sleep(full_secs)

	# Note: Since we are in a single thread environment, we assume
	# that no one will wait at the same time.
	ql.os.clear_cf()
	ql.reg.ah = 0x80

def handler(ql: Qiling):
	ah = ql.reg.ah

	leaffunc = {
		0x00 : __leaf_00,
		0x01 : __leaf_01,
		0x53 : __leaf_53,
		0x86 : __leaf_86
	}.get(ah)

	if leaffunc is None:
		ql.log.exception(f'leaf {ah:02x}h of INT 15h is not implemented')
		raise NotImplementedError()

	leaffunc(ql)
