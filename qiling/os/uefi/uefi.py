#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import logging
from unicorn import *
from unicorn.x86_const import *
from qiling.const import *
from qiling.os.os import QlOs

class QlOsUefi(QlOs):
	def __init__(self, ql):
		super(QlOsUefi, self).__init__(ql)
		self.ql = ql
		self.entry_point = 0
		self.running_module = None
		self.user_defined_api = {}
		self.user_defined_api_onenter = {}
		self.user_defined_api_onexit = {}
		self.PE_RUN = True
		self.heap = None # Will be initialized by the loader.
	
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

	def disassembler(self, address):
		dump_bytes = 64     # amount of bytes to read and hexdump
		dump_insns = 8      # amount of asm instructions to show, based on bytes read

		data = self.ql.mem.read(address, dump_bytes)

		# emit a small hexdump
		logging.error('Hexdump:')
		for i in range(0, len(data), 8):
			hexdump = ' '.join(f'{ch:02x}' for ch in data[i: i + 8])
			logging.error(f'  {address + i:08x} : {hexdump}')
		logging.error(f'')

		md = self.ql.create_disassembler()

		# emit disassembly
		logging.error('Disassembly:')
		for insn in tuple(md.disasm(data, address))[:dump_insns]:
			opcodes = ''.join(f'{ch:02x}' for ch in insn.bytes[:10])

			if len(insn.bytes) > 10:
				opcodes += '.'

			logging.error(f'  {insn.address:08x}    {opcodes:<20s}  {insn.mnemonic:<8s} {insn.op_str:s}')
		logging.error(f'')

	def emu_error(self):
		logging.error(f'')

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
			('', '', 'ss'),
		)

		sizes = (64, 32, 16, 8, 8)

		# emit cpu context
		for grp in rgroups:
			for reg, bits in zip(grp, sizes):
				logging.error(f'{reg:4s} = {self.ql.reg.read(reg):0{bits // 4}x}, ' if reg else '', end='')
			logging.error(f'')
		logging.error(f'')

		logging.error(f'PC = {self.ql.reg.arch_pc:#010x}', end='')

		containing_image = self.find_containing_image(self.ql.reg.arch_pc)
		if containing_image:
			offset = self.ql.reg.arch_pc - containing_image.base
			logging.error(f' ({containing_image.path} + {offset:#x})', end='')

		logging.error(f'')

		self.ql.mem.show_mapinfo()
		logging.error(f'')

		try:
			self.disassembler(self.ql.reg.arch_pc, 64)
		except:
			logging.error(f'Error: PC({self.ql.reg.arch_pc:#x}) is unreachable')

	def run(self):
		self.notify_before_module_execution(self.ql, self.running_module)

		if self.ql.entry_point is not None:
			self.ql.loader.entry_point = self.ql.entry_point

		if self.ql.exit_point is not None:
			self.exit_point = self.ql.exit_point

		try:
			self.ql.emu_start(self.ql.loader.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
		except KeyboardInterrupt:
			logging.info(f'Execution interrupted by user')
		except UcError:
			self.emu_error()
			raise

		if self.ql._internal_exception is not None:
			raise self.ql._internal_exception


