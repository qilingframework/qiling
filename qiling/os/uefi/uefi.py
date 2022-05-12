#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import re
from typing import Any, Callable, Iterable, Mapping, MutableSequence, Sequence, Tuple
from unicorn import UcError

from qiling import Qiling
from qiling.cc import QlCC, intel
from qiling.const import QL_INTERCEPT, QL_OS
from qiling.os.const import *
from qiling.os.memory import QlMemoryHeap
from qiling.os.os import QlOs, QlOsUtils
from qiling.os.fcall import QlFunctionCall, TypedArg

from qiling.os.uefi import guids_db
from qiling.os.uefi.smm import SmmEnv

class QlOsUefi(QlOs):
	type = QL_OS.UEFI

	def __init__(self, ql: Qiling):
		super().__init__(ql)

		self.entry_point = 0
		self.running_module: str
		self.smm: SmmEnv
		self.PE_RUN: bool
		self.heap: QlMemoryHeap	# Will be initialized by the loader.

		self.on_module_enter: MutableSequence[Callable[[str], bool]] = []
		self.on_module_exit: MutableSequence[Callable[[int], bool]] = []

		cc: QlCC = {
			32: intel.cdecl,
			64: intel.ms64
		}[ql.arch.bits](ql.arch)

		self.fcall = QlFunctionCall(ql, cc)

	def save(self):
		saved_state = super(QlOsUefi, self).save()
		saved_state['entry_point'] = self.entry_point
		return saved_state


	def restore(self, saved_state):
		super(QlOsUefi, self).restore(saved_state)
		self.entry_point = saved_state['entry_point']


	def process_fcall_params(self, targs: Iterable[TypedArg]) -> Sequence[Tuple[str, str]]:
		'''[override] Post-process function call arguments values to
		determine how to display them.

		Args:
			targs: an iterable of typed args (3-tuples: type, name, value)

		Returns: a sequence of arguments (2-tuples: name, string representation of arg value)
		'''

		def fallback(v):
			'''Use original processing method for other types.
			'''

			# the original method accepts a list and returns a list, so here we 
			# craft a list containing one 3-tuple, and extracting the single element
			# the result list contains. that element is a 2-tuple, from which we
			# only need the value
			return super(QlOsUefi, self).process_fcall_params([(None, '', v)])[0][1]

		ahandlers: Mapping[Any, Callable[[Any], str]] = {
			POINTER	: lambda v: f'{v:#010x}' if v else 'NULL',
			STRING	: lambda v: QlOsUtils.stringify(v),
			WSTRING	: lambda v: f'L{QlOsUtils.stringify(v)}',
			GUID	: lambda v: guids_db.get(v.upper(), v) if v else 'NULL'
		}

		return tuple((aname, ahandlers.get(atype, fallback)(avalue)) for atype, aname, avalue in targs)

	def notify_after_module_execution(self, nmodules: int) -> bool:
		"""Callback fired after a module has finished executing successfully.

		Args:
			nmodules: number of remaining modules to execute

		Returns: `True` if subsequent modules execution should be thwarted, `False` otherwise
		"""

		return bool(sum(callback(nmodules) for callback in self.on_module_exit))

	def notify_before_module_execution(self, module: str) -> bool:
		"""Callback fired before a module is about to start executing.

		Args:
			module: path of module to execute

		Returns: `True` if module execution should be thwarted, `False` otherwise
		"""

		return bool(sum(callback(module) for callback in self.on_module_enter))


	def emit_context(self):
		rgroups = (
			((8, 'rax'), (8, 'r8'),  (4, 'cs')),
			((8, 'rbx'), (8, 'r9'),  (4, 'ds')),
			((8, 'rcx'), (8, 'r10'), (4, 'es')),
			((8, 'rdx'), (8, 'r11'), (4, 'fs')),
			((8, 'rsi'), (8, 'r12'), (4, 'gs')),
			((8, 'rdi'), (8, 'r13'), (4, 'ss')),
			((8, 'rsp'), (8, 'r14')),
			((8, 'rbp'), (8, 'r15')),
			((8, 'rip'), )
		)

		p = re.compile(r'^((?:00)+)')

		def __emit_reg(size: int, reg: str):
			val = f'{self.ql.arch.regs.read(reg):0{size * 2}x}'
			padded = p.sub("\x1b[90m\\1\x1b[39m", val, 1)

			return f'{reg:3s} = {padded}'

		self.ql.log.error(f'CPU Context:')

		for regs in rgroups:
			self.ql.log.error(f'{" | ".join(__emit_reg(size, reg) for size, reg in regs)}')

		self.ql.log.error(f'')


	def emit_hexdump(self, address: int, data: bytearray, num_cols: int = 16):
		self.ql.log.error('Hexdump:')

		# align hexdump to numbers of columns
		pre_padding = [None] * (address % num_cols)
		post_padding = [None] * (num_cols - len(pre_padding))
		chars = pre_padding + list(data) + post_padding
		address = address & ~(num_cols - 1)

		for i in range(0, len(chars), num_cols):
			hexdump = ' '.join(f'  ' if ch is None else f'{ch:02x}' for ch in chars[i: i + num_cols])
			self.ql.log.error(f'{address + i:08x} : {hexdump}')

		self.ql.log.error(f'')


	def emit_disasm(self, address: int, data: bytearray, num_insns: int = 8):
		md = self.ql.arch.disassembler

		self.ql.log.error('Disassembly:')

		for insn in tuple(md.disasm(data, address))[:num_insns]:
			self.ql.log.error(f'{insn.address:08x} : {insn.bytes.hex():28s}  {insn.mnemonic:10s} {insn.op_str:s}')

		self.ql.log.error(f'')


	def emit_stack(self, nitems: int = 4):
		self.ql.log.error('Stack:')

		for i in range(-nitems, nitems + 1):
			offset = i * self.ql.arch.pointersize

			try:
				item = self.ql.arch.stack_read(offset)
			except UcError:
				data = '(unavailable)'
			else:
				data = f'{item:0{self.ql.arch.pointersize * 2}x}'

			self.ql.log.error(f'{self.ql.arch.regs.arch_sp + offset:08x} : {data}{" <=" if i == 0 else ""}')

		self.ql.log.error('')

	def emu_error(self):
		pc = self.ql.arch.regs.arch_pc

		try:
			data = self.ql.mem.read(pc, size=64)
		except UcError:
			pc_info = ' (unreachable)'
		else:
			self.emit_context()
			self.emit_hexdump(pc, data)
			self.emit_disasm(pc, data)

			containing_image = self.ql.loader.find_containing_image(pc)
			pc_info = f' ({containing_image.path} + {pc - containing_image.base:#x})' if containing_image else ''
		finally:
			self.ql.log.error(f'PC = {pc:#010x}{pc_info}')
			self.ql.log.error(f'')

		self.emit_stack()

		self.ql.log.error(f'Memory map:')
		for info_line in self.ql.mem.get_formatted_mapinfo():
			self.ql.log.error(info_line)


	def set_api(self, target: str, handler: Callable, intercept: QL_INTERCEPT = QL_INTERCEPT.CALL):
		super().set_api(f'hook_{target}', handler, intercept)

	def run(self):
		# TODO: this is not the right place for this
		self.smm = SmmEnv(self.ql)

		self.notify_before_module_execution(self.running_module)

		if self.ql.entry_point is not None:
			self.ql.loader.entry_point = self.ql.entry_point

		if self.ql.exit_point is not None:
			self.exit_point = self.ql.exit_point

		try:
			self.PE_RUN = True

			self.ql.emu_start(self.ql.loader.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
		except KeyboardInterrupt as ex:
			self.ql.log.critical(f'Execution interrupted by user')

			if self.ql._internal_exception is ex:
				self.ql._internal_exception = None
		except UcError:
			self.emu_error()
			raise

		if self.ql._internal_exception is not None:
			raise self.ql._internal_exception

	def stop(self) -> None:
		self.ql.emu_stop()
		self.PE_RUN = False
