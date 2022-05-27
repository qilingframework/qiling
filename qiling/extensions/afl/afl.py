from typing import List, Callable
from qiling.core import Qiling
from unicornafl import *
from qiling.exception import QlErrorNotImplemented

def ql_afl_fuzz(ql: Qiling,
                input_file: str,
                place_input_callback: Callable[["Qiling", bytes, int], bool],
                exits: List[int],
                validate_crash_callback: Callable[["Qiling", int, bytes, int], bool] = None,
                always_validate: bool = False,
                persistent_iters: int = 1):
        """ Fuzz a range of code with afl++.
            This function wraps some common logic with unicornafl.uc_afl_fuzz.
            NOTE: If no afl-fuzz instance is found, this function is almost identical to ql.run.
            :param Qiling ql: The Qiling instance.
            :param str input_file: This usually is the input file name provided by the command argument.
            :param Callable place_input_callback: This callback is triggered every time a new child is
            generated. It returns True if the input is accepted, or the input would be skipped.
            :param list exits: All possible exits.
            :param Callable validate_crash_callback: This callback is triggered every time to check if we are crashed.                     
            :param bool always_validate: If this is set to False, validate_crash_callback will be only triggered if
            uc_emu_start (which is called internally by afl_fuzz) returns an error. Or the validate_crash_callback will
            be triggered every time.
            :param int persistent_iters: Fuzz how many times before forking a new child.
            :raises UcAflError: If something wrong happens with the fuzzer.
        """

        def _ql_afl_place_input_wrapper(uc, input_bytes, iters, data):
            (ql, cb, _) = data
            if cb:
                return cb(ql, input_bytes, iters)
            else:
                return False

        def _ql_afl_validate_wrapper(uc, result, input_bytes, iters, data):
            (ql, _, cb) = data

            if cb:
                return cb(ql, result, input_bytes, iters)
            else:
                return False

        data = (ql, place_input_callback, validate_crash_callback)
        try:
            # uc_afl_fuzz will never return non-zero value.
            uc_afl_fuzz(ql.uc, 
                        input_file=input_file, 
                        place_input_callback=_ql_afl_place_input_wrapper, 
                        exits=exits, 
                        validate_crash_callback=_ql_afl_validate_wrapper, 
                        always_validate=always_validate, 
                        persistent_iters=persistent_iters,
                        data=data)
        except NameError as ex:
            raise QlErrorNotImplemented("unicornafl is not installed or AFL++ is not supported on this platform") from ex
        except UcAflError as ex:
            if ex.errno != UC_AFL_RET_CALLED_TWICE:
                # This one is special. Many fuzzing scripts start fuzzing in a Unicorn UC_HOOK_CODE callback and 
                # starts execution on the current address, which results in a duplicate UC_HOOK_CODE callback. To 
                # make unicornafl easy to use, we handle this siliently.
                #
                # For other exceptions, we raise them.
                raise