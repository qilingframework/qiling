#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from typing import Any, Callable, Optional, Mapping, Tuple

from qiling import Qiling

Resolver = Callable[[int], Tuple[Any, int]]

class QlCC:
	"""Calling convention base class.
	"""

	def __init__(self, ql: Qiling) -> None:
		"""Initialize a calling convention instance.

		Args:
			ql: qiling instance
		"""

		self.ql = ql

	def getRawParam(self, index: int) -> int:
		"""Read argument's raw value.
		It is the caller responsibility to make sure the argument exists.

		Args:
			index: argument index to read

		Returns: argument raw value
		"""

		raise NotImplementedError

	def setRawParam(self, index: int, value: int) -> None:
		"""Replace argument's raw value.
		It is the caller responsibility to make sure the argument exists.

		Args:
			index: argument index to replace
			value: new raw value to write
		"""

		raise NotImplementedError

	def getReturnValue(self) -> int:
		"""Get function return value.
		"""

		raise NotImplementedError

	def setReturnValue(self, val: int) -> None:
		"""Set function return value.

		Args:
			val: a value to set
		"""

		raise NotImplementedError

	def unwind(self) -> int:
		"""Unwind frame and return from function call.

		Returns: return address
		"""

		raise NotImplementedError

OnEnterHook = Callable[[Qiling, int, Mapping], Tuple[int, Mapping]]
OnExitHook = Callable[[Qiling, int, Mapping, int], int]

class QlFunctionCall:
	def __init__(self, ql: Qiling, cc: QlCC, resolvers: Mapping[Any, Resolver]) -> None:
		"""Initialize function call handler.

		Args:
			ql: qiling instance
			cc: calling convention instance to handle the call
			resolvers: a mapping of parameter types to methods that resolve parameters values
		"""

		self.ql = ql
		self.cc = cc
		self.resolvers = resolvers

	def getResolvedParams(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
		"""Retrieve parameters values according to their assigned type.

		Args:
			params: a mapping of parameter names to their types

		Returns: a mapping of parameter names to their assigned values
		"""

		default_resolver = self.resolvers[None]

		resolved = {}
		i = 0

		for p_name, p_type in params.items():
			resolve = self.resolvers.get(p_type, default_resolver)
			resolved[p_name], consumed = resolve(i)

			i += consumed

		return resolved

	def call(self, func: Callable, params: Mapping[str, Any], hook_onenter: Optional[OnEnterHook], hook_onexit: Optional[OnExitHook], *args) -> Tuple[Mapping, int, int]:
		"""Call a hooked function.

		Args:
			func: function hook
			params: a mapping of parameter names to their types 
			hook_onenter: a hook to call before entering function hook
			hook_onexit: a hook to call after returning from function hook

		Returns: resolved params mapping, return value, return address
		"""
		# TODO: could use func.__annotations__ to resolve parameters and return type.
		#       that would require redefining all hook functions with python annotations, but
		#       also simplify hooks code (e.g. no need to do:  x = params["x"] )

		ql = self.ql
		pc = ql.reg.arch_pc

		# replace params definitions with their actual values
		params = self.getResolvedParams(params)

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

		# unwind stack frame
		retaddr = self.cc.unwind()

		return params, retval, retaddr
