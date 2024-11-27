
from __future__ import annotations
from typing import TYPE_CHECKING, Any, Collection, Optional, Callable

from unicornafl import UcAflError, UC_AFL_RET_CALLED_TWICE, uc_afl_fuzz_custom
from unicorn import UcError, UC_ERR_OK

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented


if TYPE_CHECKING:
    from unicorn import Uc
    from ctypes import c_char, Array

InputFeedingCallback = Callable[[Qiling, bytes, int], bool]
FuzzingCallback = Callable[[Qiling], int]
CrashValidationCallback = Callable[[Qiling, int, bytes, int], bool]


def ql_afl_fuzz(ql: Qiling,
                input_file: str,
                place_input_callback: InputFeedingCallback,
                exits: Collection[int],
                validate_crash_callback: Optional[CrashValidationCallback] = None,
                always_validate: bool = False,
                persistent_iters: int = 1) -> None:
    """Fuzz a range of code with afl++.
    This function wraps some common logic with unicornafl.uc_afl_fuzz.

    Args:
        ql:                     qiling instance

        filename:               path to a file that contains an initial input data. this is usually
                                the filename provided as the fuzzer command line argument

        place_input_callback:   a callback that is triggered whenever a new child process is created
                                and about to be fed with a new fuzzing input. the callback is responsible
                                to place the newly generated stimuli (as is, or manipulated to the users'
                                need) where the fuzzed program expects to find its input: e.g. stdin,
                                memory buffer, file, etc. based on the stimuli, the callback can decide
                                whether afl should proceed with this round (returns `True`) or discard
                                it (returns `False`)

        exits:                  addresses that mark a graceful completion of the fuzzed flow

        validate_crash_callback: a callback that is triggered to check whether the emulation has crashed

        always_validate:        indicate whether the crash validating callback should be called on every
                                iteration (`True`) or only when emluation raises an exception (`False`, default)

        persistent_iters:       Reuse the same process for this many fuzzing iterations before forking
                                a new child process (default: 1)

    Raises:
        UcAflError: If something wrong happens with the fuzzer.
    """

    def __fuzzing_wrapper(ql: Qiling) -> int:
        """Emulation wrapper.
        """

        # if we are fuzzin an arm code, make sure to take the effective pc
        pc = getattr(ql.arch, 'effective_pc', ql.arch.regs.arch_pc)

        try:
            ql.arch.uc.emu_start(pc, 0)
        except UcError as err:
            return err.errno

        return UC_ERR_OK

    def __null_crash_validation(ql: Qiling, result: int, input_bytes: bytes, round: int) -> bool:
        return False

    ql_afl_fuzz_custom(
        ql,
        input_file,
        place_input_callback,
        __fuzzing_wrapper,
        exits,
        validate_crash_callback or __null_crash_validation,
        always_validate,
        persistent_iters)


def ql_afl_fuzz_custom(ql: Qiling,
                       input_file: str,
                       place_input_callback: InputFeedingCallback,
                       fuzzing_callback: FuzzingCallback,
                       exits: Collection[int],
                       validate_crash_callback: CrashValidationCallback,
                       always_validate: bool = False,
                       persistent_iters: int = 1):

    def __place_input_wrapper(uc: Uc, input_bytes: Array[c_char], iters: int, context: Any) -> bool:
        return place_input_callback(ql, input_bytes.raw, iters)

    def __validate_crash_wrapper(uc: Uc, result: int, input_bytes: bytes, iters: int, context: Any) -> bool:
        return validate_crash_callback(ql, result, input_bytes, iters)

    def __fuzzing_wrapper(uc: Uc, context: Any) -> int:
        return fuzzing_callback(ql)

    uc = ql.arch.uc
    uc.ctl_exits_enabled(True)
    uc.ctl_set_exits(exits)

    try:
        uc_afl_fuzz_custom(
            uc,
            input_file,
            __place_input_wrapper,
            __fuzzing_wrapper,
            __validate_crash_wrapper,
            always_validate,
            persistent_iters,
            None)

    except NameError as ex:
        raise QlErrorNotImplemented('unicornafl is not installed or AFL++ is not supported on this platform') from ex

    except UcAflError as ex:
        if ex.errno != UC_AFL_RET_CALLED_TWICE:
            # many fuzzing scripts start fuzzing with a Unicorn UC_HOOK_CODE callback and while
            # starting execution at the current address. that results in a duplicated UC_HOOK_CODE
            # callback. we handle this case siliently for simplicity
            #
            # For other exceptions, we raise them.
            raise
