#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, pickle
from typing import TYPE_CHECKING, Any, AnyStr, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# See https://stackoverflow.com/questions/39740632/python-type-hinting-without-cyclic-imports
if TYPE_CHECKING:
    from os import PathLike
    from unicorn.unicorn import Uc
    from configparser import ConfigParser
    from logging import Logger
    from .arch.arch import QlArch
    from .os.os import QlOs
    from .os.memory import QlMemoryManager
    from .hw.hw import QlHwManager
    from .loader.loader import QlLoader

from .const import QL_ARCH, QL_ENDIAN, QL_OS, QL_STOP, QL_VERBOSE, QL_ARCH_INTERPRETER, QL_OS_BAREMETAL
from .exception import QlErrorFileNotFound, QlErrorArch, QlErrorOsType
from .host import QlHost
from .log import *
from .utils import *
from .core_struct import QlCoreStructs
from .core_hooks import QlCoreHooks

# Mixin Pattern
class Qiling(QlCoreHooks, QlCoreStructs):
    def __init__(
            self,
            argv: Sequence[str] = None,
            rootfs: str = r'.',
            env: MutableMapping[AnyStr, AnyStr] = {},
            code: bytes = None,
            ostype: Union[str, QL_OS] = None,
            archtype: Union[str, QL_ARCH] = None,
            verbose: QL_VERBOSE = QL_VERBOSE.DEFAULT,
            profile: str = None,
            console: bool = True,
            log_file=None,
            log_override=None,
            log_plain: bool = False,
            multithread: bool = False,
            filter = None,
            stop: QL_STOP = QL_STOP.NONE,
            *,
            endian: Optional[QL_ENDIAN] = None,
            thumb: bool = False,
            libcache: bool = False
    ):
        """ Create a Qiling instance.

            For each argument or property, please refer to its help. e.g. help(Qiling.multithread)
        """

        ##################################
        # Definition during ql=Qiling()  #
        ##################################
        self._env = env
        self._code = code
        self._multithread = multithread
        self._log_filter = None
        self._internal_exception = None
        self._stop_options = stop

        ##################################
        # Definition after ql=Qiling()   #
        ##################################
        self._patch_bin = []
        self._patch_lib = []
        self._debug_stop = False
        self._debugger = False

        ###############################
        # Properties configured later #
        ###############################
        self.entry_point = None
        self.exit_point = None
        self.timeout = None
        self.count = None
        self._initial_sp = None

        """
        Qiling Framework Core Engine
        """
        ##############
        # argv setup #
        ##############
        if argv is None:
            argv = ['qilingcode']

        elif not os.path.exists(argv[0]):
            raise QlErrorFileNotFound(f'Target binary not found: "{argv[0]}"')

        self._argv = argv
        self._path = self.argv[0]
        self._targetname = os.path.basename(self.path)

        ################
        # rootfs setup #
        ################
        if not os.path.exists(rootfs):
            raise QlErrorFileNotFound(f'Target rootfs not found: "{rootfs}"')

        self._rootfs = rootfs

        #################
        # arch os setup #
        #################
        self._host = QlHost()

        if type(archtype) is str:
            archtype = arch_convert(archtype)

        if type(ostype) is str:
            ostype = os_convert(ostype)

        # if provided arch was invalid or not provided, guess arch and os
        if archtype is None:
            guessed_archtype, guessed_ostype, guessed_archendian = ql_guess_emu_env(self.path)

            archtype = guessed_archtype

            if ostype is None:
                ostype = guessed_ostype

            if endian is None:
                endian = guessed_archendian

        # if arch was set but os was not, try to guess it by arch
        elif ostype is None:
            ostype = arch_os_convert(archtype)

        # arch should have been determined by now; fail if not
        if type(archtype) is not QL_ARCH:
            raise QlErrorArch(f'Unknown or unsupported architecture: "{archtype}"')

        # os should have been determined by now; fail if not
        if type(ostype) is not QL_OS:
            raise QlErrorOsType(f'Unknown or unsupported operating system: "{ostype}"')

        # if endianess is still undetermined, set it to little-endian.
        # this setting is ignored for architectures with predefined endianess
        if endian is None:
            endian = QL_ENDIAN.EL

        self._arch = select_arch(archtype, endian, thumb)(self)

        # Once we finish setting up arch, we can init QlCoreStructs and QlCoreHooks
        if not self.interpreter:
            QlCoreStructs.__init__(self, self.arch.endian, self.arch.bits)
            QlCoreHooks.__init__(self, self.uc)

        ##########
        # Logger #
        ##########
        self._log_file_fd = setup_logger(self, log_file, console, log_override, log_plain)

        self.filter = filter
        self.verbose = verbose

        ###########
        # Profile #
        ###########
        self.log.debug(f'Profile: {profile or "default"}')
        self._profile = profile_setup(ostype, profile)

        ##########
        # Loader #
        ##########
        self._loader = select_loader(ostype, libcache)(self)

        ##############
        # Components #
        ##############
        if not self.interpreter:
            self._mem = select_component('os', 'memory')(self)
            self._os = select_os(ostype)(self)

        if self.baremetal:
            self._hw = select_component('hw', 'hw')(self)

        # Run the loader
        self.loader.run()

        self._init_stop_guard()

    #####################
    # Qiling Components #
    #####################

    @property
    def mem(self) -> "QlMemoryManager":
        """ Qiling memory manager.

            Example: ql.mem.read(0xdeadbeaf, 4)
        """
        return self._mem

    @property
    def hw(self) -> "QlHwManager":
        """ Qiling hardware manager.

            Example: 
        """
        return self._hw


    @property
    def arch(self) -> "QlArch":
        """ Qiling architecture layer.

            Also see qiling/arch/<arch>.py
        """
        return self._arch

    @property
    def loader(self) -> "QlLoader":
        """ Qiling loader layer.

            Also see qiling/loader/<filetype>.py
        """
        return self._loader

    @property
    def os(self) -> "QlOs":
        """ Qiling os layer.

            Also see qiling/os/<os>/<os>.py
        """
        return self._os

    @property
    def log(self) -> "Logger":
        """ Returns the logger this Qiling instance uses.

            You can override this log by passing `log_override=your_log` to Qiling.__init__

            Type: logging.Logger
            Example: ql.log.info("This goes to terminal")
        """
        return self._log_file_fd

    ##################
    # Qiling Options #
    ##################

    # If an option doesn't have a setter, it means that it can be only set during Qiling.__init__

    @property
    def multithread(self) -> bool:
        """ Specify whether multithread has been enabled.

            WARNING: This property shouldn't be set after Qiling.__init__.

            Type: bool
            Example: Qiling(multithread=True)
        """
        return self._multithread

    @property
    def profile(self) -> "ConfigParser":
        """ Program profile. See qiling/profiles/*.ql for details.

            Note: Please pass None or the path string to Qiling.__init__.

            Type: ConfigParser
            Value: str
            Example: Qiling(profile="profiles/dos.ql")
        """
        return self._profile

    @property
    def argv(self) -> Sequence[str]:
        """ The program argv.

            Example: Qiling(argv=['/bin/ls', '-a'])
        """
        return self._argv

    @property
    def rootfs(self) -> str:
        """ The program rootfs. For some common rootfs, see examples/rootfs/ for details.

            Type: str
            Example: Qiling(argv=['/bin/ls', '-a'], rootfs='examples/rootfs/x8664_linux/')
        """
        return self._rootfs

    @property
    def env(self) -> MutableMapping[AnyStr, AnyStr]:
        """ The program environment variables.

            Example: Qiling(env={"LC_ALL" : "en_US.UTF-8"})
        """
        return self._env

    @property
    def code(self) -> bytes:
        """ The shellcode to execute.

            Note: It can't be used with "argv" parameter.

            Type: bytes
            Example: Qiling(code=b"\x90", ostype="macos", archtype="x8664")
        """
        return self._code

    @property
    def path(self) -> str:
        """ The file path of the executable.

            Type: str
        """
        return self._path

    @property
    def targetname(self) -> str:
        """ The target name of the executable. e.g. "c.exe" in "a\b\c.exe"

            Type: str
        """
        return self._targetname

    @property
    def interpreter(self) -> bool:
        """ Interpreter Engine
            - Blockchain related
            - Java engine?

            Type: bool
        """
        return self.arch.type in QL_ARCH_INTERPRETER

    @property
    def baremetal(self) -> bool:
        """ MCU / Bare Metal type
            - STM32, RTOS

            Type: bool
        """

        # os is not initialized for interpreter archs
        if self.interpreter:
            return False

        return self.os.type in QL_OS_BAREMETAL

    @property
    def host(self) -> QlHost:
        """Provide an interface to the hosting platform where Qiling runs on.
        """

        return self._host

    @property
    def internal_exception(self) -> Optional[Exception]:
        """ Internal exception catched during Unicorn callback. Not intended for regular users.

            Type: Exception
        """
        return self._internal_exception

    @property
    def verbose(self) -> QL_VERBOSE:
        """Set verbosity level.

        Values:
            `QL_VERBOSE.DISABLED`: turn off logging
            `QL_VERBOSE.OFF`     : mask off anything below warnings, errors and critical severity
            `QL_VERBOSE.DEFAULT` : info logging level; default verbosity
            `QL_VERBOSE.DEBUG`   : debug logging level; higher verbosity
            `QL_VERBOSE.DISASM`  : debug verbosity along with disassembly trace (slow!)
            `QL_VERBOSE.DUMP`    : disassembly trace along with cpu context dump
        """
        return self._verbose

    @verbose.setter
    def verbose(self, v: QL_VERBOSE):
        self._verbose = v

        self.log.setLevel(resolve_logger_level(v))
        self.arch.utils.setup_output(v)

    @property
    def patch_bin(self) -> List[Tuple[int, bytes]]:
        """ Return the patches for binary.

            Type: list
        """
        return self._patch_bin

    @property
    def patch_lib(self) -> List[Tuple[int, bytes, str]]:
        """ Return the patches for library.

            Type: list
        """
        return self._patch_lib

    @property
    def debug_stop(self) -> bool:
        """ Stop if some syscalls is not implemented.

            Note: This option is broken on some archs.

            Type: bool
            Example: ql.debug_stop = True
        """
        return self._debug_stop

    @debug_stop.setter
    def debug_stop(self, enabled: bool):
        self._debug_stop = enabled

    @property
    def debugger(self) -> bool:
        return bool(self._debugger)

    @debugger.setter
    def debugger(self, dbger: Union[str, bool]):
        """ Enable debugger.

            Values:
              - "gdb": enable gdb.
              - True : an alias to "gdb".
              - "gdb:0.0.0.0:1234" : gdb which listens on 0.0.0.0:1234
              - "qdb": enable qdb.
              - "qdb:rr": enable qdb with reverse debugging support.

            Example: ql.debugger = True
                     ql.debugger = "qdb"
        """
        self._debugger = dbger

    @property
    def filter(self) -> str:
        """ Filter logs with regex.
            Type: str
            Example: - Qiling(filter=r'^exit')
                     - ql.filter = r'^open'
        """

        lf = self._log_filter

        return '' if lf is None else lf._filter.pattern

    @filter.setter
    def filter(self, regex: Optional[str]):
        if regex is None:
            if self._log_filter is not None:
                self.log.removeFilter(self._log_filter)

        else:
            if self._log_filter is None:
                self._log_filter = RegexFilter(regex)

                self.log.addFilter(self._log_filter)

            self._log_filter.update_filter(regex)

    @property
    def uc(self) -> 'Uc':
        """ Raw uc instance.

            Type: Uc
        """
        return self.arch.uc

    @property
    def stop_options(self) -> QL_STOP:
        """ The stop options configured (multiple options apply):
            - `QL_STOP.STACK_POINTER` : Stop execution on a negative stackpointer
            - `QL_STOP.EXIT_TRAP`     : Stop execution when the pc value enters a guarded region

        Returns: configured options
        """
        return self._stop_options

    def do_bin_patch(self):
        ba = self.loader.load_address

        for offset, code in self.patch_bin:
            self.mem.write(ba + offset, code)

    def do_lib_patch(self):
        for offset, code, filename in self.patch_lib:
            ba = self.mem.get_lib_base(filename)

            if ba is None:
                raise RuntimeError(f'Patch failed: there is no loaded library named "{filename}"')

            self.mem.write(ba + offset, code)

    def _init_stop_guard(self):
        if not self.stop_options:
            return

        # Allocate a guard page, we need this in both cases
        # On a negative stack pointer, we still need a return address (otherwise we end up at 0)
        # Make sure it is not close to the heap (PE), otherwise the heap cannot grow
        self._exit_trap_addr = self.mem.find_free_space(0x1000, minaddr=0x9000000, align=0x10)
        self.mem.map(self._exit_trap_addr, 0x1000, info='[Stop guard page]')

        # Stop on a negative stack pointer
        if QL_STOP.STACK_POINTER in self.stop_options:
            def _check_sp(ql: Qiling, address: int, size: int):
                if not ql.loader.skip_exit_check:
                    if ql._initial_sp < ql.arch.regs.arch_sp:
                        self.log.info('Process returned from entrypoint (stackpointer)!')
                        ql.emu_stop()

            self.hook_code(_check_sp)

        # Stop when running to exit trap address
        if QL_STOP.EXIT_TRAP in self.stop_options:
            def _exit_trap(ql: Qiling):
                self.log.info('Process returned from entrypoint (exit_trap)!')
                ql.emu_stop()

            self.hook_address(_exit_trap, self._exit_trap_addr)

    def write_exit_trap(self):
        self._initial_sp = self.arch.regs.arch_sp

        if self.stop_options:
            if not self.loader.skip_exit_check:
                self.log.debug(f'Setting up exit trap at {self._exit_trap_addr:#x}')
                self.stack_write(0, self._exit_trap_addr)

            elif QL_STOP.EXIT_TRAP in self.stop_options:
                self.log.debug(f'Loader requested to skip exit_trap!')


    ###############
    # Qiling APIS #
    ###############

    def run(self, begin: Optional[int] = None, end: Optional[int] = None, timeout: int = 0, count: int = 0):
        """Start binary emulation.

        Args:
            begin   : emulation starting address
            end     : emulation ending address
            timeout : limit emulation to a specific amount of time (microseconds); unlimited by default
            count   : limit emulation to a specific amount of instructions; unlimited by default
        """

        # replace the original entry point, exit point, timeout and count
        self.entry_point = begin
        self.exit_point = end
        self.timeout = timeout
        self.count = count

        # init debugger (if set)
        debugger = select_debugger(self._debugger)

        if debugger:
            debugger = debugger(self)

        # patch binary
        self.do_bin_patch()

        if self.baremetal:
            if self.count <= 0:
                self.count = -1

            self.arch.run(count=self.count, end=self.exit_point)
        else:
            self.write_exit_trap()
            # emulate the binary
            self.os.run()

        # run debugger
        if debugger and self.debugger:
            debugger.run()


    # patch code to memory address
    def patch(self, offset: int, data: bytes, target: str = None) -> None:
        """Volatilely patch binary and libraries with arbitrary content.
        Patching may be done prior to emulation start.

        Args:
            offset: offset in target to patch
            data: patch data
            target: target library name to patch (or `None` for the main executable binary)
        """

        if target is None:
            self.patch_bin.append((offset, data))
        else:
            self.patch_lib.append((offset, data, target))


    # save all qiling instance states
    def save(self, reg=True, mem=True, fd=False, cpu_context=False, os=False, loader=False, *, snapshot: str = None):
        saved_states = {}

        if reg:
            saved_states["reg"] = self.arch.regs.save()

        if mem:
            saved_states["mem"] = self.mem.save()

        if fd:
            saved_states["fd"] = self.os.fd.save()

        if cpu_context:
            saved_states["cpu_context"] = self.arch.save()

        if os:
            saved_states["os"] = self.os.save()

        if loader:
            saved_states["loader"] = self.loader.save()

        if snapshot is not None:
            with open(snapshot, "wb") as save_state:
                pickle.dump(saved_states, save_state)

        return saved_states


    # restore states qiling instance from saved_states
    def restore(self, saved_states: Mapping[str, Any] = {}, *, snapshot: str = None):

        # snapshot will be ignored if saved_states is set
        if (not saved_states) and (snapshot is not None):
            with open(snapshot, "rb") as load_state:
                saved_states = pickle.load(load_state)

        if "mem" in saved_states:
            self.mem.restore(saved_states["mem"])

        if "cpu_context" in saved_states:
            self.arch.restore(saved_states["cpu_context"])

        if "reg" in saved_states:
            self.arch.regs.restore(saved_states["reg"])

        if "fd" in saved_states:
            self.os.fd.restore(saved_states["fd"])

        if "os_context" in saved_states:
            self.os.restore(saved_states["os_context"])

        if "loader" in saved_states:
            self.loader.restore(saved_states["loader"])


    # Map "ql_path" to any objects which implements QlFsMappedObject.
    def add_fs_mapper(self, ql_path: Union["PathLike", str], real_dest):
        self.os.fs_mapper.add_fs_mapping(ql_path, real_dest)

    # Remove "ql_path" mapping.
    def remove_fs_mapper(self, ql_path: Union["PathLike", str]):
        self.os.fs_mapper.remove_fs_mapping(ql_path)
    
    # push to stack bottom, and update stack register
    def stack_push(self, data):
        return self.arch.stack_push(data)


    # pop from stack bottom, and update stack register
    def stack_pop(self):
        return self.arch.stack_pop()


    # read from stack, at a given offset from stack bottom
    # NOTE: unlike stack_pop(), this does not change stack register
    def stack_read(self, offset):
        return self.arch.stack_read(offset)


    # write to stack, at a given offset from stack bottom
    # NOTE: unlike stack_push(), this does not change stack register
    def stack_write(self, offset, data):
        return self.arch.stack_write(offset, data)


    # stop emulation
    def emu_stop(self):
        self.uc.emu_stop()
    
    # stop emulation
    def stop(self):
        if self.multithread:
            self.os.thread_management.stop() 

        elif self.baremetal:
            self.arch.stop()

        else:
            self.uc.emu_stop()    

    # start emulation
    def emu_start(self, begin: int, end: int, timeout: int = 0, count: int = 0):
        """Start emulation.

        Args:
            begin   : emulation starting address
            end     : emulation ending address
            timeout : max emulation time (in microseconds); unlimited by default
            count  : max emulation steps (instructions count); unlimited by default
        """

        if self._arch.type in (QL_ARCH.ARM, QL_ARCH.CORTEX_M) and self._arch._init_thumb:
            begin |= 1

        self.uc.emu_start(begin, end, timeout, count)

        if self._internal_exception is not None:
            raise self._internal_exception
