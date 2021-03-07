#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from typing import Any, Callable, MutableMapping, Optional, Mapping, Tuple, Sequence

from qiling import Qiling
from qiling.os.const import PARAM_INT8, PARAM_INT16, PARAM_INT32, PARAM_INT64, PARAM_INTN
from qiling.refactored.cc import QlCC

Reader = Callable[[int], Tuple[int, int]]
CallHook = Callable[[Qiling, int, Mapping], int]
OnEnterHook = Callable[[Qiling, int, Mapping], Tuple[int, Mapping]]
OnExitHook = Callable[[Qiling, int, Mapping, int], int]

class QlFunctionCall:
	def __init__(self, ql: Qiling, cc: QlCC, readers: Mapping[int, Reader] = {}) -> None:
		"""Initialize function call handler.

		Args:
			ql: qiling instance
			cc: calling convention instance to handle the call
			readers: a mapping of parameter types to methods that access their values (optional)
		"""

		self.ql = ql
		self.cc = cc

		__readers = {
			 8: cc.getRawParam8,
			16: cc.getRawParam16,
			32: cc.getRawParam32,
			64: cc.getRawParam64,
			 0: cc.getRawParam
		}

		def __make_reader(nbits: int) -> Reader:
			rd = __readers[nbits]
			ns = cc.getNumSlots(nbits)

			return lambda si: (rd(si), ns)

		# default parameter reading accessors
		self.readers: MutableMapping[int, Reader] = {
			PARAM_INT8 : __make_reader(8),
			PARAM_INT16: __make_reader(16),
			PARAM_INT32: __make_reader(32),
			PARAM_INT64: __make_reader(64),
			PARAM_INTN : __make_reader(0)
		}

		# let the user override default readers or add custom ones
		self.readers.update(readers)

	def readParams(self, ptypes: Sequence[Any]) -> Sequence[int]:
		"""Walk the function parameters list and get their values.

		Args:
			ptypes: a sequence of parameters types to read

		Returns: parameters raw values
		"""

		default = self.readers[PARAM_INTN]

		si = 0
		values = []

		for typ in ptypes:
			value, consumed = self.readers.get(typ, default)(si)
			si += consumed

			values.append(value)

		return values

	# TODO: turn writeParams into a generic method like readParams
	def writeParams(self, values: Sequence[int]) -> None:
		for si, val in enumerate(values):
			self.cc.setRawParam(si, val)

	def call(self, func: CallHook, params: Mapping[str, Any], hook_onenter: Optional[OnEnterHook], hook_onexit: Optional[OnExitHook], passthru: bool, *args) -> Tuple[Mapping, int, int]:
		"""Call a hooked function.

		Args:
			func: function hook
			params: a mapping of parameter names to their values 
			hook_onenter: a hook to call before entering function hook
			hook_onexit: a hook to call after returning from function hook
			passthru: whether to skip stack frame unwinding
			...: additional arguments to pass to hooks and func

		Returns: resolved params mapping, return value, return address
		"""

		ql = self.ql
		pc = ql.reg.arch_pc

		# if set, fire up the on-enter hook and let it override original args set
		if hook_onenter:
			overrides = hook_onenter(ql, pc, params, *args)

			if overrides is not None:
				pc, params = overrides

		# call function
		retval = func(ql, pc, params, *args)

		# if set, fire up the on-exit hook and let it override the return value
		if hook_onexit:
			override = hook_onexit(ql, pc, params, retval, *args)

			if override is not None:
				retval = override

		# set return value
		if retval is not None:
			self.cc.setReturnValue(retval)

		# TODO: resolve return value

		# FIXME: though usually one slot is used for each fcall parameter, this is not
		# always true (for example, a 64 bits parameter in a 32 bits system). this should
		# reflect the true number of slots used by this set of parameters
		#
		# unwind stack frame
		retaddr = -1 if passthru else self.cc.unwind(len(params))

		return params, retval, retaddr
