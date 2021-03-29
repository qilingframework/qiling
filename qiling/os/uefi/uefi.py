#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import UcError

from qiling import Qiling
from qiling.cc import QlCC, intel
from qiling.os.os import QlOs
from qiling.os.fcall import QlFunctionCall

class QlOsUefi(QlOs):
	def __init__(self, ql: Qiling):
		super().__init__(ql)

		self.entry_point = 0
		self.running_module = None
		self.PE_RUN = True
		self.heap = None # Will be initialized by the loader.

		cc: QlCC = {
			32: intel.cdecl,
			64: intel.ms64
		}[ql.archbit](ql)

		self.fcall = QlFunctionCall(ql, cc)

	def save(self):
		saved_state = super(QlOsUefi, self).save()
		saved_state['entry_point'] = self.entry_point
		return saved_state


	def restore(self, saved_state):
		super(QlOsUefi, self).restore(saved_state)
		self.entry_point = saved_state['entry_point']


	@staticmethod
	def notify_after_module_execution(ql, number_of_modules_left):
		return False


	@staticmethod
	def notify_before_module_execution(ql, module):
		ql.os.running_module = module
		return False


	def emit_context(self):
		# TODO: add xmm, ymm, zmm registers
		rgroups = (
			('rax', 'eax', 'ax', 'ah', 'al'),
			('rbx', 'ebx', 'bx', 'bh', 'bl'),
			('rcx', 'ecx', 'cx', 'ch', 'cl'),
			('rdx', 'edx', 'dx', 'dh', 'dl'),
			('rsi', 'esi', 'si', ''),  # BUG: sil is missing
			('rdi', 'edi', 'di', ''),  # BUG: dil is missing
			('rsp', 'esp', 'sp', ''),  # BUG: spl is missing
			('rbp', 'ebp', 'bp', ''),  # BUG: bpl is missing
			('rip', 'eip', 'ip', ''),
			(),
			('r8',  'r8d',  'r8w',  'r8b' ),
			('r9',  'r9d',  'r9w',  'r9b' ),
			('r10', 'r10d', 'r10w', 'r10b'),
			('r11', 'r11d', 'r11w', 'r11b'),
			('r12', 'r12d', 'r12w', 'r12b'),
			('r13', 'r13d', 'r13w', 'r13b'),
			('r14', 'r14d', 'r14w', 'r14b'),
			('r15', 'r15d', 'r15w', 'r15b'),
			(),
			('', '', 'cs'),
			('', '', 'ds'),
			('', '', 'es'),
			('', '', 'fs'),
			('', '', 'gs'),
			('', '', 'ss')
		)

		sizes = (64, 32, 16, 8, 8)

		self.ql.log.error(f'CPU Context:')

		for grp in rgroups:
			self.ql.log.error(', '.join((f'{reg:4s} = {self.ql.reg.read(reg):0{bits // 4}x}') for reg, bits in zip(grp, sizes) if reg))

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
		md = self.ql.create_disassembler()

		self.ql.log.error('Disassembly:')

		for insn in tuple(md.disasm(data, address))[:num_insns]:
			opcodes = ''.join(f'{ch:02x}' for ch in insn.bytes[:10])

			if len(insn.bytes) > 10:
				opcodes += '.'

			self.ql.log.error(f'{insn.address:08x} :  {opcodes:<20s}  {insn.mnemonic:<10s} {insn.op_str:s}')

		self.ql.log.error(f'')


	def emu_error(self):
		dump_len = 64

		try:
			pc = self.ql.reg.arch_pc
			data = self.ql.mem.read(pc, dump_len)

			self.emit_context()
			self.emit_hexdump(pc, data)
			self.emit_disasm(pc, data)

			containing_image = self.find_containing_image(pc)
			img_info = f' ({containing_image.path} + {pc - containing_image.base:#x})' if containing_image else ''
			self.ql.log.error(f'PC = {pc:#010x}{img_info}')

			self.ql.log.error(f'Memory map:')
			self.ql.mem.show_mapinfo()
		except UcError:
			self.ql.log.error(f'Error: PC({pc:#x}) is unreachable')


	def run(self):
		self.notify_before_module_execution(self.ql, self.running_module)

		if self.ql.entry_point is not None:
			self.ql.loader.entry_point = self.ql.entry_point

		if self.ql.exit_point is not None:
			self.exit_point = self.ql.exit_point

		try:
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
