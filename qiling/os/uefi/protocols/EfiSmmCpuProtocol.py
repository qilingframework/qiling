#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from ..fncc import *
from ..ProcessorBind import *
from ..UefiBaseType import *
from ..const import *

# @see: MdePkg/Include/Protocol/MmCpu.h
class EFI_SMM_SAVE_STATE_REGISTER(ENUM_UC):
	_members_ = {
		# note: members names were shorten from 'EFI_SMM_SAVE_STATE_REGISTER_regname' to just 'regname' 
		'GDTBASE'	: 4,
		'IDTBASE'	: 5,
		'LDTBASE'	: 6,
		'GDTLIMIT'	: 7,
		'IDTLIMIT'	: 8,
		'LDTLIMIT'	: 9,
		'LDTINFO'	: 10,

		'ES'		: 20,
		'CS'		: 21,
		'SS'		: 22,
		'DS'		: 23,
		'FS'		: 24,
		'GS'		: 25,
		'LDTR_SEL'	: 26,
		'TR_SEL'	: 27,
		'DR7'		: 28,
		'DR6'		: 29,
		'R8'		: 30,
		'R9'		: 31,
		'R10'		: 32,
		'R11'		: 33,
		'R12'		: 34,
		'R13'		: 35,
		'R14'		: 36,
		'R15'		: 37,
		'RAX'		: 38,
		'RBX'		: 39,
		'RCX'		: 40,
		'RDX'		: 41,
		'RSP'		: 42,
		'RBP'		: 43,
		'RSI'		: 44,
		'RDI'		: 45,
		'RIP'		: 46,

		'RFLAGS'	: 51,
		'CR0'		: 52,
		'CR3'		: 53,
		'CR4'		: 54,

		'FCW'		: 256,
		'FSW'		: 257,
		'FTW'		: 258,
		'OPCODE'	: 259,
		'FP_EIP'	: 260,
		'FP_CS'		: 261,
		'DATAOFFSET': 262,
		'FP_DS'		: 263,
		'MM0'		: 264,
		'MM1'		: 265,
		'MM2'		: 266,
		'MM3'		: 267,
		'MM4'		: 268,
		'MM5'		: 269,
		'MM6'		: 270,
		'MM7'		: 271,
		'XMM0'		: 272,
		'XMM1'		: 273,
		'XMM2'		: 274,
		'XMM3'		: 275,
		'XMM4'		: 276,
		'XMM5'		: 277,
		'XMM6'		: 278,
		'XMM7'		: 279,
		'XMM8'		: 280,
		'XMM9'		: 281,
		'XMM10'		: 282,
		'XMM11'		: 283,
		'XMM12'		: 284,
		'XMM13'		: 285,
		'XMM14'		: 286,
		'XMM15'		: 287,

		'IO'			: 512,
		'LMA'			: 513,
		'PROCESSOR_ID'	: 514
	}

# EFI_SUCCESS			The register was written from Save State
# EFI_NOT_FOUND			The register is not defined for the Save State of Processor
# EFI_INVALID_PARAMETER	ProcessorIndex or Width is not correct

@dxeapi(params = {
	"This"		: POINTER,	# EFI_SMM_CPU_PROTOCOL
	"Width"		: ULONGLONG,# UINTN
	"Register"	: INT,		# EFI_SMM_SAVE_STATE_REGISTER
	"CpuIndex"	: ULONGLONG,# UINTN
	"Buffer"	: POINTER	# PTR(VOID))
})
def hook_SmmReadSaveState(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"This"		: POINTER,	# EFI_SMM_CPU_PROTOCOL
	"Width"		: ULONGLONG,# UINTN
	"Register"	: INT,		# EFI_SMM_SAVE_STATE_REGISTER
	"CpuIndex"	: ULONGLONG,# UINTN
	"Buffer"	: POINTER	# PTR(VOID))
})
def hook_SmmWriteSaveState(ql, address, params):
	return EFI_SUCCESS

class EFI_SMM_CPU_PROTOCOL(STRUCT):
	EFI_SMM_CPU_PROTOCOL = STRUCT

	_fields_ = [
		('SmmReadSaveState',	FUNCPTR(PTR(EFI_SMM_CPU_PROTOCOL), UINTN, EFI_SMM_SAVE_STATE_REGISTER, UINTN, PTR(VOID))),
		('SmmWriteSaveState',	FUNCPTR(PTR(EFI_SMM_CPU_PROTOCOL), UINTN, EFI_SMM_SAVE_STATE_REGISTER, UINTN, PTR(VOID)))
	]

descriptor = {
	"guid" : "eb346b97-975f-4a9f-8b22-f8e92bb3d569",
	"struct" : EFI_SMM_CPU_PROTOCOL,
	"fields" : (
		("SmmReadSaveState",	hook_SmmReadSaveState),
		("SmmWriteSaveState",	hook_SmmWriteSaveState)
	)
}
