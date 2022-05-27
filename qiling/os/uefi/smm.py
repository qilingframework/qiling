#!/usr/bin/python3

from typing import Any, Callable, Iterator, Mapping, Tuple

from unicorn.unicorn_const import UC_PROT_ALL, UC_PROT_NONE
from unicorn.x86_const import *

from qiling import Qiling
from qiling.os.const import POINTER
from qiling.os.memory import QlMemoryHeap
from qiling.os.uefi import utils
from qiling.os.uefi.context import SmmContext
from qiling.os.uefi.protocols.EfiSmmCpuProtocol import EFI_SMM_SAVE_STATE_REGISTER
from qiling.os.uefi.protocols.EfiSmmSwDispatch2Protocol import EFI_SMM_SW_REGISTER_CONTEXT, EFI_SMM_SW_CONTEXT

class SaveStateArea:
	# SSA map for x64; note that it does not include all register enumerated in
	# EFI_SMM_SAVE_STATE_REGISTER, but only the most commonly used ones
	#
	# see: Intel SDM vol. 3 chapter 30.4.1.1
	offsets = {
		EFI_SMM_SAVE_STATE_REGISTER.GDTBASE	: 0x7E8C,
		EFI_SMM_SAVE_STATE_REGISTER.IDTBASE	: 0x7E94,
		EFI_SMM_SAVE_STATE_REGISTER.LDTBASE	: 0x7E9C,
		EFI_SMM_SAVE_STATE_REGISTER.GDTLIMIT: 0x7DD0,
		EFI_SMM_SAVE_STATE_REGISTER.IDTLIMIT: 0x7DD8,
		EFI_SMM_SAVE_STATE_REGISTER.LDTLIMIT: 0x7DD4,
		# EFI_SMM_SAVE_STATE_REGISTER.LDTINFO	: ?,

		EFI_SMM_SAVE_STATE_REGISTER.ES		: 0x7FA8,
		EFI_SMM_SAVE_STATE_REGISTER.CS		: 0x7FAC,
		EFI_SMM_SAVE_STATE_REGISTER.SS		: 0x7FB0,
		EFI_SMM_SAVE_STATE_REGISTER.DS		: 0x7FB4,
		EFI_SMM_SAVE_STATE_REGISTER.FS		: 0x7FB8,
		EFI_SMM_SAVE_STATE_REGISTER.GS		: 0x7FBC,
		EFI_SMM_SAVE_STATE_REGISTER.LDTR_SEL: 0x7FC0,
		EFI_SMM_SAVE_STATE_REGISTER.TR_SEL	: 0x7FC4,
		EFI_SMM_SAVE_STATE_REGISTER.DR7		: 0x7FC8,
		EFI_SMM_SAVE_STATE_REGISTER.DR6		: 0x7FD0,
		EFI_SMM_SAVE_STATE_REGISTER.R8		: 0x7F54,
		EFI_SMM_SAVE_STATE_REGISTER.R9		: 0x7F4C,
		EFI_SMM_SAVE_STATE_REGISTER.R10		: 0x7F44,
		EFI_SMM_SAVE_STATE_REGISTER.R11		: 0x7F3C,
		EFI_SMM_SAVE_STATE_REGISTER.R12		: 0x7F34,
		EFI_SMM_SAVE_STATE_REGISTER.R13		: 0x7F2C,
		EFI_SMM_SAVE_STATE_REGISTER.R14		: 0x7F24,
		EFI_SMM_SAVE_STATE_REGISTER.R15		: 0x7F1C,
		EFI_SMM_SAVE_STATE_REGISTER.RAX		: 0x7F5C,
		EFI_SMM_SAVE_STATE_REGISTER.RBX		: 0x7F74,
		EFI_SMM_SAVE_STATE_REGISTER.RCX		: 0x7F64,
		EFI_SMM_SAVE_STATE_REGISTER.RDX		: 0x7F6C,
		EFI_SMM_SAVE_STATE_REGISTER.RSP		: 0x7F7C,
		EFI_SMM_SAVE_STATE_REGISTER.RBP		: 0x7F84,
		EFI_SMM_SAVE_STATE_REGISTER.RSI		: 0x7F8C,
		EFI_SMM_SAVE_STATE_REGISTER.RDI		: 0x7F94,
		EFI_SMM_SAVE_STATE_REGISTER.RIP		: 0x7FD8,

		EFI_SMM_SAVE_STATE_REGISTER.RFLAGS	: 0x7FE8,
		EFI_SMM_SAVE_STATE_REGISTER.CR0		: 0x7FF8,
		EFI_SMM_SAVE_STATE_REGISTER.CR3		: 0x7FF0,
		EFI_SMM_SAVE_STATE_REGISTER.CR4		: 0x7E40
	}

	def __init__(self, ql: Qiling):
		self.ql = ql

		self.ssa_base = ql.loader.smm_context.smram_base + 0x8000
		self.ssa_size = 0x8000

		# map smram save state area, but do not make it available just yet
		if ql.mem.is_available(self.ssa_base, self.ssa_size):
			ql.mem.map(self.ssa_base, self.ssa_size, UC_PROT_NONE, '[SMRAM SSA]')

	def read(self, regidx: EFI_SMM_SAVE_STATE_REGISTER, width: int) -> bytes:
		"""Retrieve a register value from SMM save state area.
		"""

		reg = self.ssa_base + SaveStateArea.offsets[regidx]

		return self.ql.mem.read(reg, width)

	def write(self, regidx: EFI_SMM_SAVE_STATE_REGISTER, data: bytes) -> None:
		"""Replace a register value in SMM save state area.
		"""

		reg = self.ssa_base + SaveStateArea.offsets[regidx]

		self.ql.mem.write(reg, data)

class SmmEnv:
	SSA_REG_MAP = {
		UC_X86_REG_ES	: (4, EFI_SMM_SAVE_STATE_REGISTER.ES),
		UC_X86_REG_CS	: (4, EFI_SMM_SAVE_STATE_REGISTER.CS),
		UC_X86_REG_SS	: (4, EFI_SMM_SAVE_STATE_REGISTER.SS),
		UC_X86_REG_DS	: (4, EFI_SMM_SAVE_STATE_REGISTER.DS),
		UC_X86_REG_FS	: (4, EFI_SMM_SAVE_STATE_REGISTER.FS),
		UC_X86_REG_GS	: (4, EFI_SMM_SAVE_STATE_REGISTER.GS),
		UC_X86_REG_R8	: (8, EFI_SMM_SAVE_STATE_REGISTER.R8),
		UC_X86_REG_R9	: (8, EFI_SMM_SAVE_STATE_REGISTER.R9),
		UC_X86_REG_R10	: (8, EFI_SMM_SAVE_STATE_REGISTER.R10),
		UC_X86_REG_R11	: (8, EFI_SMM_SAVE_STATE_REGISTER.R11),
		UC_X86_REG_R12	: (8, EFI_SMM_SAVE_STATE_REGISTER.R12),
		UC_X86_REG_R13	: (8, EFI_SMM_SAVE_STATE_REGISTER.R13),
		UC_X86_REG_R14	: (8, EFI_SMM_SAVE_STATE_REGISTER.R14),
		UC_X86_REG_R15	: (8, EFI_SMM_SAVE_STATE_REGISTER.R15),
		UC_X86_REG_RAX	: (8, EFI_SMM_SAVE_STATE_REGISTER.RAX),
		UC_X86_REG_RBX	: (8, EFI_SMM_SAVE_STATE_REGISTER.RBX),
		UC_X86_REG_RCX	: (8, EFI_SMM_SAVE_STATE_REGISTER.RCX),
		UC_X86_REG_RDX	: (8, EFI_SMM_SAVE_STATE_REGISTER.RDX),
		UC_X86_REG_RSP	: (8, EFI_SMM_SAVE_STATE_REGISTER.RSP),
		UC_X86_REG_RBP	: (8, EFI_SMM_SAVE_STATE_REGISTER.RBP),
		UC_X86_REG_RSI	: (8, EFI_SMM_SAVE_STATE_REGISTER.RSI),
		UC_X86_REG_RDI	: (8, EFI_SMM_SAVE_STATE_REGISTER.RDI),
		UC_X86_REG_RIP	: (8, EFI_SMM_SAVE_STATE_REGISTER.RIP),
		UC_X86_REG_EFLAGS : (8, EFI_SMM_SAVE_STATE_REGISTER.RFLAGS),
		UC_X86_REG_CR0	: (8, EFI_SMM_SAVE_STATE_REGISTER.CR0),
		UC_X86_REG_CR3	: (8, EFI_SMM_SAVE_STATE_REGISTER.CR3),
		UC_X86_REG_CR4	: (8, EFI_SMM_SAVE_STATE_REGISTER.CR4)
	}

	def __init__(self, ql: Qiling):
		self.ql = ql
		self.ssa = SaveStateArea(ql)

		# by default the system is out of smm
		self.active = False

	def __mapped_smram_ranges(self) -> Iterator[Tuple[int, int]]:
		"""Iterate through all mapped ranges enclosed within SMRAM.
		"""

		context: SmmContext = self.ql.loader.smm_context

		smram_lbound = context.smram_base
		smram_ubound = smram_lbound + context.smram_size

		for lbound, ubound, *_ in self.ql.mem.get_mapinfo():
			if (smram_lbound <= lbound) and (ubound <= smram_ubound):
				yield lbound, ubound

	def enter(self) -> None:
		"""Enter SMM.

		Save CPU state and unlock SMM resources.
		"""

		self.ql.log.info(f'Entering SMM')

		assert not self.active, 'SMM is not reentrant'

		# unlock smram ranges for access
		for lbound, ubound in self.__mapped_smram_ranges():
			self.ql.mem.protect(lbound, ubound - lbound, UC_PROT_ALL)

		# write cpu state to ssa (partially)
		# that can take place only after smram ranges have been unlocked
		for ucreg, (width, regidx) in SmmEnv.SSA_REG_MAP.items():
			val = self.ql.arch.regs.read(ucreg)

			pack = {
				8 : self.ql.pack64,
				4 : self.ql.pack32,
				2 : self.ql.pack16,
				1 : self.ql.pack8
			}[width]

			self.ssa.write(regidx, pack(val))

		# let os know that the code is now executing in smm
		self.active = True

	def leave(self) -> None:
		"""Leave SMM.

		Restore CPU state and lock SMM resources.
		"""

		self.ql.log.info(f'Leaving SMM')

		# restore cpu state from ssa (partially)
		# that can take place only before smram ranges have been locked
		for ucreg, (width, regidx) in SmmEnv.SSA_REG_MAP.items():
			data = self.ssa.read(regidx, width)

			unpack = {
				8 : self.ql.unpack64,
				4 : self.ql.unpack32,
				2 : self.ql.unpack16,
				1 : self.ql.unpack8
			}[width]

			self.ql.arch.regs.write(ucreg, unpack(data))

		# lock smram ranges for access
		for lbound, ubound in self.__mapped_smram_ranges():
			self.ql.mem.protect(lbound, ubound - lbound, UC_PROT_NONE)

		# let os know that the code is no longer executing in smm
		self.active = False

	def invoke_swsmi(self, cpu: int, idx: int, entry: int, args: Mapping[str, Any], *, onexit: Callable[[Qiling], None] = None) -> None:
		"""Invoke a native SWSMI handler.

		Args:
			cpu: initiating logical processor index
			idx: swsmi index
			entry: swsmi handler entry point
			args: data arguments collected on handler registration
			onexit: optionally specify a method to call on handler exit
		"""

		ql = self.ql
		heap: QlMemoryHeap = self.ql.loader.smm_context.heap

		self.enter()

		DispatchHandle	= args['DispatchHandle']
		Context			= heap.alloc(EFI_SMM_SW_REGISTER_CONTEXT.sizeof())
		CommBuffer		= heap.alloc(EFI_SMM_SW_CONTEXT.sizeof())
		CommBufferSize	= heap.alloc(ql.arch.pointersize)

		# setup Context
		args['RegisterContext'].saveTo(ql, Context)

		# setup CommBuffer
		SmmSwContext = EFI_SMM_SW_CONTEXT()
		SmmSwContext.SwSmiCpuIndex = cpu
		SmmSwContext.CommandPort = idx
		SmmSwContext.DataPort = 0
		SmmSwContext.saveTo(ql, CommBuffer)

		# setup CommBufferSize
		utils.ptr_write64(ql, CommBufferSize, SmmSwContext.sizeof())

		# clean up handler resources
		def __cleanup(ql: Qiling):
			ql.log.info(f'Leaving SWSMI handler {idx:#04x}')

			# unwind ms64 shadow space
			ql.arch.regs.arch_sp += (4 * ql.arch.pointersize)

			# release handler resources
			heap.free(DispatchHandle)
			heap.free(Context)
			heap.free(CommBuffer)
			heap.free(CommBufferSize)

			# release hook
			heap.free(cleanup_trap)
			hret.remove()

			self.leave()

			# if specified, call on-exit callback
			if onexit:
				onexit(ql)

		# hook returning from swsmi handler
		cleanup_trap = heap.alloc(ql.arch.pointersize)
		hret = ql.hook_address(__cleanup, cleanup_trap)

		ql.log.info(f'Entering SWSMI handler {idx:#04x}')

		# invoke the swsmi handler
		ql.os.fcall.call_native(entry, (
			(POINTER, DispatchHandle),
			(POINTER, Context),
			(POINTER, CommBuffer),
			(POINTER, CommBufferSize)
		), cleanup_trap)
