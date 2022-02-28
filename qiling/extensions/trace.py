#!/usr/bin/python3

# More info, please refer to https://github.com/qilingframework/qiling/pull/765

from collections import deque
from typing import Deque, Iterable, Iterator, Mapping, Tuple

from capstone import Cs, CsInsn, CS_ARCH_X86, CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from capstone.x86 import X86Op
from capstone.x86_const import X86_INS_LEA, X86_REG_INVALID, X86_REG_RIP

from qiling import Qiling

TraceRecord = Tuple[CsInsn, Iterable[Tuple[int, int]]]

# <WORKAROUND>
def __uc2_workaround() -> Mapping[int, int]:
	"""Starting from Unicorn2, Unicorn and Capstone Intel registers definitions are
	no longer aligned and cannot be used interchangebly. This temporary workaround
	maps capstone x86 registers definitions to unicorn x86 registers definitions.

	see: https://github.com/unicorn-engine/unicorn/issues/1492
	"""

	from capstone import x86_const as cs_x86_const
	from unicorn import x86_const as uc_x86_const

	def __canonicalized_mapping(module, prefix: str) -> Mapping[str, int]:
		return dict((k[len(prefix):], getattr(module, k)) for k in dir(module) if k.startswith(prefix))

	cs_x86_regs = __canonicalized_mapping(cs_x86_const, 'X86_REG')
	uc_x86_regs = __canonicalized_mapping(uc_x86_const, 'UC_X86_REG')

	return dict((cs_x86_regs[k], uc_x86_regs[k]) for k in cs_x86_regs if k in uc_x86_regs)

CS_UC_REGS = __uc2_workaround()
# </WORKAROUND>

def __get_trace_records(ql: Qiling, address: int, size: int, md: Cs) -> Iterator[TraceRecord]:
	"""[private] Acquire trace info for the current instruction and yield as a trace record.
	A trace record is a parsed instruction paired to a list of registers and their values.

	This method might yield more than one record for a single instruction.
	"""

	# unicorn denotes unsupported instructions by a magic size value. though these instructions
	# are not emulated, capstone can still parse them.
	if size == 0xf1f1f1f1:
		# note that invalid instructions will generate a StopIteration exception here
		yield next(__get_trace_records(ql, address, 16, md))
		return

	# a trace line is generated even for hook addresses that do not contain meaningful opcodes.
	# in that case, make it look like a nop
	if address in ql._addr_hook:
		buf = b'\x90'
	else:
		buf = ql.mem.read(address, size)

	for insn in md.disasm(buf, address):
		# BUG: insn.regs_read doesn't work well, so we use insn.regs_access()[0]
		state = tuple((reg, ql.arch.regs.read(CS_UC_REGS[reg])) for reg in insn.regs_access()[0])

		yield (insn, state)

def __to_trace_line(record: TraceRecord, symsmap: Mapping[int, str] = {}) -> str:
	"""[private] Transform trace info into a formatted trace line.
	"""

	insn, state = record

	# when the rip register is referenced from within an instruction it is expected to point
	# to the next instruction boundary. since unicorn has not executed the instruction yet
	# is uses the cpu state resulted from the previous instruction - and rip points to the
	# current instruction instead of the next one.
	#
	# here we patch rip value recorded in state to point to the next instruction boundary
	state = tuple((reg, val + insn.size if reg == X86_REG_RIP else val) for reg, val in state)

	def __read_reg(reg: int) -> int:
		"""[internal] Read a register value from the recorded state. Only registers that were
		referenced by the current instruction can be read.
		"""

		return 0 if reg == X86_REG_INVALID else next(v for r, v in state if r == reg)

	def __resolve(address: int) -> str:
		"""[internal] Find the symbol that matches to the specified address (if any).
		"""

		return symsmap.get(address, '')

	def __parse_op(op: X86Op) -> str:
		"""[internal] Parse an operand and return its string representation. Indirect memory
		references will be substitued by the effective address they refer to. If the referenced
		address is associated with a symbol, it will be substitued by that symbol.
		"""

		if op.type == CS_OP_REG:
			return insn.reg_name(op.value.reg)

		elif op.type == CS_OP_IMM:
			imm = op.value.imm

			return __resolve(imm) or f'{imm:#x}'

		elif op.type == CS_OP_MEM:
			mem = op.value.mem

			base  = __read_reg(mem.base)
			index = __read_reg(mem.index)
			scale = mem.scale
			disp  = mem.disp

			ea = base + index * scale + disp

			# we construct the string representation for each operand; denote memory
			# dereferenes with the appropriate 'ptr' prefix. the 'lea' instruction is
			# an exception since it does not use that notation.
			if insn.id == X86_INS_LEA:
				qualifier = f''
			else:
				ptr = {
					1: 'byte',
					2: 'word',
					4: 'dword',
					8: 'qword',
					10: 'fword',
					16: 'xmmword'
				}[op.size]

				qualifier = f'{ptr} ptr '

			return f'{qualifier}[{__resolve(ea) or f"{ea:#x}"}]'

		# unexpected op type
		raise RuntimeError

	operands = ', '.join(__parse_op(o) for o in insn.operands)
	reads = ', '.join(f'{insn.reg_name(reg)} = {val:#x}' for reg, val in state)

	return f'{insn.address:08x} | {insn.bytes.hex():24s} {insn.mnemonic:10} {operands:56s} | {reads}'

def enable_full_trace(ql: Qiling):
	"""Enable instruction-level tracing.

	Trace line will be emitted for each instruction before it gets executed. The info
	includes static data along with the relevant registers state and symbols resolving.

	Args:
		ql: qiling instance
	"""

	# enable detailed disassembly info
	md = ql.arch.disassembler
	md.detail = True

	assert md.arch == CS_ARCH_X86, 'currently available only for intel architecture'

	# if available, use symbols map to resolve memory accesses
	symsmap = getattr(ql.loader, 'symsmap', {})

	# show trace lines in a darker color so they would be easily distinguished from
	# ordinary log records
	faded_color = "\033[2m"
	reset_color = "\033[0m"

	def __trace_hook(ql: Qiling, address: int, size: int):
		"""[internal] Trace hook callback.
		"""

		for record in __get_trace_records(ql, address, size, md):
			line = __to_trace_line(record, symsmap)

			ql.log.debug(f'{faded_color}{line}{reset_color}')

	ql.hook_code(__trace_hook)

def enable_history_trace(ql: Qiling, nrecords: int):
	"""Enable instruction-level tracing in history mode.

	To allow faster execution, the trace info collected throughout program execution is not
	emitted and undergo as minimal post-processing as possible. When program crahses, the
	last `nrecords` trace lines are shown.

	Args:
		ql: qiling instance
		nrecords: number of last records to show
	"""

	# enable detailed disassembly info
	md = ql.arch.disassembler
	md.detail = True

	assert md.arch == CS_ARCH_X86, 'currently available only for intel architecture'

	# if available, use symbols map to resolve memory accesses
	symsmap = getattr(ql.loader, 'symsmap', {})

	history: Deque[TraceRecord] = deque(maxlen=nrecords)

	def __trace_hook(ql: Qiling, address: int, size: int):
		"""[internal] Trace hook callback.
		"""

		history.extend(__get_trace_records(ql, address, size, md))

	ql.hook_code(__trace_hook)

	# replace the emulation error handler with our own so we can emit the trace
	# records when program crashes. before we do that, we save the original one
	# so we can call it.

	orig_emu_error = ql.os.emu_error

	def __emu_error(*args):
		# first run the original emulation error handler
		orig_emu_error(*args)

		# then parse and emit the trace info we collected
		ql.log.error(f'History:')
		for record in history:
			line = __to_trace_line(record, symsmap)

			ql.log.error(line)

		ql.log.error(f'')

	ql.os.emu_error = __emu_error
