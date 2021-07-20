#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling import Qiling

from .. import utils

# exit
def __leaf_4c(ql: Qiling):
	ql.log.info("Program terminated gracefully")
	ql.emu_stop()

# write a character to screen
def __leaf_02(ql: Qiling):
	ch = ql.reg.dl
	ql.reg.al = ch

	print(f'{ch:c}', end='')

# write a string to screen
def __leaf_09(ql: Qiling):
	print(utils.read_dos_string_from_ds_dx(ql))

# clear input buffer
def __leaf_0c(ql: Qiling):
	pass

# set interrupt vector
def __leaf_25(ql: Qiling):
	pass

# create psp
def __leaf_26(ql: Qiling):
	pass

# get dos version
def __leaf_30(ql: Qiling):
	ql.reg.ax = ql.os.dos_ver

# get or set ctrl-break
def __leaf_33(ql: Qiling):
	pass

# get interrupt vector
def __leaf_35(ql: Qiling):
	pass

# open file for write
def __leaf_3c(ql: Qiling):
	# fileattr ignored
	fname = utils.read_dos_string_from_ds_dx(ql)
	fpath = ql.os.path.transform_to_real_path(fname)

	ql.os.handles[ql.os.handle_next] = open(fpath, "wb")
	ql.reg.ax = ql.os.handle_next
	ql.os.handle_next += 1
	ql.os.clear_cf()

# open file for read
def __leaf_3d(ql: Qiling):
	fname = utils.read_dos_string_from_ds_dx(ql)
	fpath = ql.os.path.transform_to_real_path(fname)

	ql.os.handles[ql.os.handle_next] = open(fpath, "rb")
	ql.reg.ax = ql.os.handle_next
	ql.os.handle_next += 1
	ql.os.clear_cf()

# close file
def __leaf_3e(ql: Qiling):
	hd = ql.reg.bx

	if hd in ql.os.handles:
		f = ql.os.handles.pop(hd)
		f.close()

		ql.os.clear_cf()
	else:
		ql.reg.ax = 0x06
		ql.os.set_cf()

# read from file
def __leaf_3f(ql: Qiling):
	hd = ql.reg.bx

	if hd in ql.os.handles:
		f = ql.os.handles[hd]
		buffer = utils.linaddr(ql.reg.ds, ql.reg.dx)
		sz = ql.reg.cx
		rd = f.read(sz)
		ql.mem.write(buffer, rd)
		ql.os.clear_cf()
		ql.reg.ax = len(rd)
	else:
		ql.reg.ax = 0x06
		ql.os.set_cf()

# write to file
def __leaf_40(ql: Qiling):
	hd = ql.reg.bx

	if hd in ql.os.handles:
		f = ql.os.handles[hd]
		buffer = utils.linaddr(ql.reg.ds, ql.reg.dx)
		sz = ql.reg.cx
		rd = ql.mem.read(buffer, sz)
		f.write(bytes(rd))
		ql.os.clear_cf()
		ql.reg.ax = len(rd)
	else:
		ql.reg.ax = 0x06
		ql.os.set_cf()

# delete file
def __leaf_41(ql: Qiling):
	fname = utils.read_dos_string_from_ds_dx(ql)
	fpath = ql.os.path.transform_to_real_path(fname)

	try:
		os.remove(fpath)
		ql.os.clear_cf()
	except OSError:
		ql.reg.ax = 0x05
		ql.os.set_cf()

def __leaf_43(ql: Qiling):
	ql.reg.cx = 0xffff
	ql.os.clear_cf()

def handler(ql: Qiling):
	ah = ql.reg.ah

	leaffunc = {
		0x02 : __leaf_02,
		0x06 : __leaf_02,
		0x09 : __leaf_09,
		0x0c : __leaf_0c,
		0x25 : __leaf_25,
		0x26 : __leaf_26,
		0x30 : __leaf_30,
		0x33 : __leaf_33,
		0x35 : __leaf_35,
		0x3c : __leaf_3c,
		0x3d : __leaf_3d,
		0x3e : __leaf_3e,
		0x3f : __leaf_3f,
		0x40 : __leaf_40,
		0x41 : __leaf_41,
		0x43 : __leaf_43,
		0x4c : __leaf_4c
	}.get(ah)

	if leaffunc is None:
		ql.log.exception(f'leaf {ah:02x}h of INT 21h is not implemented')
		raise NotImplementedError()

	leaffunc(ql)
