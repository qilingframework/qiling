from __future__ import annotations

from typing import Any, Callable

from unicorn.unicorn_const import (
    UC_HOOK_CODE,
)

from qiling import Qiling
from qiling.core_hooks import TraceHookCalback
from qiling.core_hooks_types import Hook, HookRet


class HookSwitch(Hook):
    def __init__(self, callback, user_data=None, begin: int = 1, end: int = 0) -> None:
        super().__init__(callback=callback, user_data=user_data, begin=begin, end=end)
        self.switch = False

    def bound_check(self, pc: int, size: int = 1) -> bool:
        if self.begin == pc and not self.switch:
            self.switch = True
        if self.end == pc and self.switch:
            self.switch = False
        return self.switch


def ql_hook_switch(
    ql: Qiling, callback: Callable, user_data: Any = None, begin: int = 1, end: int = 0
) -> HookRet:
    hook = HookSwitch(callback=callback, user_data=user_data, begin=begin, end=end)
    ql._ql_hook(UC_HOOK_CODE, hook)

    return HookRet(ql=ql, hook_type=UC_HOOK_CODE, hook_obj=hook)


def hook_switch(
    ql: Qiling,
    callback: TraceHookCalback,
    user_data: Any = None,
    begin: int = 1,
    end: int = 0,
) -> HookRet:
    """Intercept assembly instructions before they get executed.

    Args:
        ql        : an instance of the Qiling class
        callback  : a method to call upon interception
        user_data : an additional context to pass to callback (default: `None`)
        begin     : the memory address from when to start watching
        end       : the memory address from when to stop watching

    Notes:
        If `begin` and `end` are not specified, the hook will never execute, use
        `hook_code` instead.
        If 'begin' and 'end' are the same address, the hook will never execute, use
        `hook_address` instead.

    Returns:
        Hook handle
    """

    return ql_hook_switch(
        ql=ql, callback=callback, user_data=user_data, begin=begin, end=end
    )
