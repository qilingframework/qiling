#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from datetime import datetime

from qiling import Qiling

from .. import utils

def __set_elapsed_ticks(ql: Qiling):
	now = datetime.now()
	ticks = int((now - ql.os.start_time).total_seconds() * ql.os.ticks_per_second)

	ql.reg.cx = (ticks >> 16) & 0xffff
	ql.reg.dx = (ticks >>  0) & 0xffff

def __leaf_00(ql: Qiling):
	__set_elapsed_ticks(ql)

	ql.reg.al = 0

def __leaf_01(ql: Qiling):
	__set_elapsed_ticks(ql)

def __leaf_02_03(ql: Qiling):
	now = datetime.now()

	ql.reg.ch = utils.BIN2BCD(now.hour)
	ql.reg.cl = utils.BIN2BCD(now.minute)
	ql.reg.dh = utils.BIN2BCD(now.second)
	ql.reg.dl = 0

	ql.os.clear_cf()

def __leaf_04_05(ql: Qiling):
	now = datetime.now()

	# See https://sites.google.com/site/liangweiqiang/Home/e5006/e5006classnote/jumptiming/int1ahclockservice
	ql.reg.ch = utils.BIN2BCD((now.year - 1) // 100)
	ql.reg.cl = utils.BIN2BCD(now.year % 100)
	ql.reg.dh = utils.BIN2BCD(now.month)
	ql.reg.dl = utils.BIN2BCD(now.day)

	ql.os.clear_cf()

def __leaf_06_07_09(ql: Qiling):
	# TODO: Implement clock interrupt.
	ql.os.set_cf()

def __leaf_08(ql: Qiling):
	pass

def __leaf_0a(ql: Qiling):
	now = datetime.now()

	ql.reg.cx = (now - datetime(1980, 1, 1)).days

def __leaf_0b(ql: Qiling):
	pass

def handler(ql: Qiling):
	ah = ql.reg.ah

	leaffunc = {
		0x00 : __leaf_00,
		0x01 : __leaf_01,
		0x02 : __leaf_02_03,
		0x03 : __leaf_02_03,
		0x04 : __leaf_04_05,
		0x05 : __leaf_04_05,
		0x06 : __leaf_06_07_09,
		0x07 : __leaf_06_07_09,
		0x08 : __leaf_08,
		0x09 : __leaf_06_07_09,
		0x0a : __leaf_0a,
		0x0b : __leaf_0b
	}.get(ah)

	if leaffunc is None:
		ql.log.exception(f'leaf {ah:02x}h of INT 1Ah is not implemented')
		raise NotImplementedError()

	leaffunc(ql)
