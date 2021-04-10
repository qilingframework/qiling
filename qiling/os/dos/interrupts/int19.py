#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def handler(ql: Qiling):
	# Note: Memory is not cleaned.
	dl = ql.reg.dl

	if ql.os.fs_mapper.has_mapping(dl):
		disk = ql.os.fs_mapper.open(dl, None)
		disk.lseek(0, 0)
		mbr = disk.read(512)
	else:
		with open(ql.path, "rb") as f:
			mbr = f.read()

	ql.mem.write(0x7C00, mbr)

	ql.reg.cs = 0x07C0
	ql.reg.ip = 0x0000
