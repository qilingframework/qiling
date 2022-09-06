#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def __leaf_13(self):
	pass

def handler(ql: Qiling):
	ah = ql.reg.ah

	leaffunc = {
		0x13 : __leaf_13
	}.get(ah)

	if leaffunc is None:
		ql.log.exception(f'leaf {ah:02x}h of INT 20h is not implemented')
		raise NotImplementedError()

	leaffunc(ql)
