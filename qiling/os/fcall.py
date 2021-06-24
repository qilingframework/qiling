#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from typing import Any, Callable, Iterable, MutableMapping, Optional, Mapping, Tuple, Sequence

from qiling import Qiling
from qiling.cc import QlCC
from qiling.os.const import PARAM_INT8, PARAM_INT16, PARAM_INT32, PARAM_INT64, PARAM_INTN

Reader = Callable[[int], int]
Writer = Callable[[int, int], None]
Accessor = Tuple[Reader, Writer, int]

CallHook = Callable[[Qiling, int, Mapping], int]
OnEnterHook = Callable[[Qiling, int, Mapping], Tuple[int, Mapping]]
OnExitHook = Callable[[Qiling, int, Mapping, int], int]

TypedArg = Tuple[Any, str, Any]

class QlFunctionCall:
	def __init__(self, ql: Qiling, cc: QlCC, accessors: Mapping[int, Accessor] = {}) -> None:
		"""Initialize function call handler.

		Args:
			ql: qiling instance
			cc: calling convention instance to handle the call
			accessors: a mapping of parameter types to methods that read and write their values (optional)
		"""

		self.ql = ql
		self.cc = cc

		def __make_accessor(nbits: int) -> Accessor:
			reader = lambda si: cc.getRawParam(si, nbits or None)
			writer = lambda si, val: cc.setRawParam(si, val, nbits or None)
			nslots = cc.getNumSlots(nbits)

			return (reader, writer, nslots)

		# default parameter accessors: readers, writers and slots count
		self.accessors: MutableMapping[int, Accessor] = {
			PARAM_INT8 : __make_accessor(8),
			PARAM_INT16: __make_accessor(16),
			PARAM_INT32: __make_accessor(32),
			PARAM_INT64: __make_accessor(64),
			PARAM_INTN : __make_accessor(0)
		}

		# let the user override default accessors or add custom ones
		self.accessors.update(accessors)

	def readParams(self, ptypes: Sequence[Any]) -> Sequence[int]:
		"""Walk the function parameters list and get their values.

		Args:
			ptypes: a sequence of parameters types to read

		Returns: parameters raw values
		"""

		default = self.accessors[PARAM_INTN]

		si = 0
		values = []

		for typ in ptypes:
			read, _, nslots = self.accessors.get(typ, default)

			val = read(si)
			si += nslots

			values.append(val)

		return values

	def writeParams(self, params: Sequence[Tuple[Any, int]]) -> None:
		"""Walk the function parameters list and set their values.

		Args:
			params: a sequence of 2-tuples containing parameters types and values
		"""

		default = self.accessors[PARAM_INTN]

		si = 0

		for typ, val in params:
			_, write, nslots = self.accessors.get(typ, default)

			write(si, val)
			si += nslots

	def __count_slots(self, ptypes: Iterable[Any]) -> int:
		default = self.accessors[PARAM_INTN]

		return sum(self.accessors.get(typ, default)[2] for typ in ptypes)

	@staticmethod
	def __get_typed_args(proto: Mapping[str, Any], args: Mapping[str, Any]) -> Iterable[TypedArg]:
		types = list(proto.values())
		names = list(args.keys())
		values = list(args.values())

		# variadic functions are invoked with unknown set of arguments which
		# do not explicitly appear in prototype (there is an ellipsis instead).
		#
		# when a hooked variadic function is called, it updates the arguments
		# mapping with the additional arguments it was given. that makes the
		# arguments mapping longer than the prototype mapping; in other words:
		# at this point we may have more values and names than types.
		#
		# here we expand the types list to meet names length, in such a case.
		if len(names) > len(types):
			types.extend([None] * (len(names) - len(types)))

		return zip(types, names, values)

	def call(self, func: CallHook, proto: Mapping[str, Any], params: Mapping[str, Any], hook_onenter: Optional[OnEnterHook], hook_onexit: Optional[OnExitHook], passthru: bool) -> Tuple[Iterable[TypedArg], int, int]:
		"""Execute a hooked function.

		Args:
			func: function hook
			proto: function's parameters types list
			params: a mapping of parameter names to their values 
			hook_onenter: a hook to call before entering function hook
			hook_onexit: a hook to call after returning from function hook
			passthru: whether to skip stack frame unwinding

		Returns: resolved params mapping, return value, return address
		"""

		ql = self.ql
		pc = ql.reg.arch_pc

		# if set, fire up the on-enter hook and let it override original args set
		if hook_onenter:
			overrides = hook_onenter(ql, pc, params)

			if overrides is not None:
				pc, params = overrides

		# call function
		retval = func(ql, pc, params)

		# if set, fire up the on-exit hook and let it override the return value
		if hook_onexit:
			override = hook_onexit(ql, pc, params, retval)

			if override is not None:
				retval = override

		# set return value
		if retval is not None:
			self.cc.setReturnValue(retval)

		targs = QlFunctionCall.__get_typed_args(proto, params)

		# TODO: resolve return value

		# unwind stack frame; note that function prototype sometimes does not
		# reflect the actual number of arguments passed to the function, like
		# in variadic functions (e.g. printf-like functions). in such case the
		# function frame would not be unwinded entirely and cause the program
		# to fail or produce funny results.
		# 
		# nevertheless this type of functions never unwind their own frame,
		# exactly for the reason they are not aware of the actual number of
		# arguments they got. since the caller is responsible for unwinding
		# we should be good.

		nslots = self.__count_slots(proto.values())
		retaddr = -1 if passthru else self.cc.unwind(nslots)

		return targs, retval, retaddr
