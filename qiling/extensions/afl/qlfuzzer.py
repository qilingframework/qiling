# @author: elicn

import os

from abc import ABC, abstractmethod
from typing import Any, Collection, Dict, Optional, Sequence

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import afl
from qiling.os.const import POINTER


class QlFuzzer(ABC):
    """Simplify Qiling-based fuzzing.

    Subclass it to easily implement a custom Qiling-based fuzzer.
    """

    @staticmethod
    def __set_default(params: Dict[str, Any], name: str, value: Any) -> None:
        """Set a default value to an option whose value was not specified.

        Args:
            params: kwargs dictionary to modify
            name: option name
            value: default value to set

        Returns: None. however `params` dictionary is modified
        """

        if name not in params:
            params[name] = value

    def __init__(self, argv: Sequence[str], rootfs: str, **kwargs) -> None:
        """Initialize fuzzer instance.

        Parameters are identical to Qiling init.
        """

        # unless explicitly set otherwise, tune qiling for maximum performance
        self.__set_default(kwargs, 'verbose', QL_VERBOSE.DISABLED)
        self.__set_default(kwargs, 'log_devices', [])
        self.__set_default(kwargs, 'console', False)

        self.ql = Qiling(argv, rootfs, **kwargs)

    def __install_crash_hooks(self, crashes: Collection[int]) -> None:
        """Hook certain locations in code and make them simulate a crash so AFL would recognize
        them as meaningful targets.

        Args:
            crashes: executable addresses to hook
        """

        def __crash(ql: Qiling) -> None:
            os.abort()

        for address in crashes:
            self.ql.hook_address(__crash, address)

    def __install_kickoff_hook(self, infilename: str, entry: int, exits: Collection[int]) -> None:
        def __kickoff(ql: Qiling):
            """Have Unicorn forked and start instrumentation.
            """

            # this is just a one-time hook; remove it
            ko_hook.remove()

            afl.ql_afl_fuzz(ql, infilename, self.feed_input, exits)

        # set afl instrumentation [re]starting point
        ko_hook = self.ql.hook_address(__kickoff, entry)

    def stage_call_site(self, params: Sequence[int]) -> None:
        """Stage parameters for a function call.
        This method provides a convinient way to set up parameters when fuzzing a function call.

        Args:
            params: a sequence of integer values to set as parameters
        """

        self.ql.os.fcall.writeParams([(POINTER, p) for p in params])

    @abstractmethod
    def feed_input(self, ql: Qiling, stimuli: bytes, pround: int) -> bool:
        """A callback method invoked by AFL whenever a new fuzzing stimuli is generated.
        The method may manipulate the stimuli to its needs or use it as-is, and ultimately
        responsible to place it where the fuzzed program expects its input to be found, e.g.:
        stdin, file, socket, memory, etc.

        Args:
            ql: qiling instance
            stimuli: newly generated input to the fuzzed program
            pround: iteration number within a persistent session. if persistency was not set,
            round value is expected to be 0 every time

        Returns: a boolean indicator of whether AFL should proceed with this fuzzing iteration
        or not (i.e. in case the generated stimuli does not satisfy fuzzing logic criteria)
        """

    def ea(self, offset: int, module: Optional[str] = None, *, casefold: bool = False) -> int:
        """Get the effective address of a file offset.

        Args:
            offset: file offset
            module: module basename (the emulated binary, by default)
            casefold: match module name case-insensitively. this becomes useful when windows
            binaries load their libraries using arbitrary case names

        Returns: the effective address of `offset` using `module` base address.
        Raises: `KeyError` if the requested module was not loaded
        """

        image = self.ql.loader.get_image_by_name(module or os.path.basename(self.ql.argv[0]), casefold=casefold)

        if image is None:
            raise KeyError(f'could not find a loaded module named "{module}"')

        return image.base + offset

    def setup(self, infilename: str, entry: int, exits: Collection[int], crashes: Optional[Collection[int]] = None) -> None:
        """Set up the fuzzing parameters.

        Args:
            infilename: path of a file that contains an initial fuzzing input which does not crash
            entry: fuzzing entry point. this is where AFL will keep resetting to on each iteration
            exits: fuzzing exit points. reaching either one of these addresses means the fuzzing
            iteration has ended gracefully and AFL should start a new one
            crashes: simulate a crash on these addresses to make AFL mark it as a successfull case.
            this is useful to mark "fuzzing points of interest" that would be otherwise overlooked
            by AFL since they do not crash the program

        Notes:
            - starting a fuzzing session without calling this method first will result in a dry-run
        """

        # set up hooks to simulate crashes
        if crashes is not None:
            self.__install_crash_hooks(crashes)

        # hook the fuzzing entry address to kick-off AFL
        self.__install_kickoff_hook(infilename, entry, exits)

    def run(self, begin: Optional[int] = None) -> None:
        """Start the fuzzing session.

        Args:
            begin: emulation starting point. this may or may not be the same as the fuzzing entry
            point, depending on whether the fuzzed code reply on global resources or prior
            initialization. For example, fuzzing a 'main' function would require prior code to
            initialize argc and argv, as opposed to a stand-alone (pure) function that only needs
            its arguments and does not need any prior initialization to happen first.
            If not set, emulation will start from the default starting point.
        """

        self.ql.run(begin)
