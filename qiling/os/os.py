#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
from typing import Any, Hashable, Iterable, Optional, Callable, Mapping, Sequence, TextIO, Tuple

from unicorn import UcError

from qiling import Qiling
from qiling.const import QL_OS, QL_INTERCEPT, QL_OS_POSIX
from qiling.os.const import STRING, WSTRING, GUID
from qiling.os.fcall import QlFunctionCall, TypedArg

from .filestruct import ql_file
from .mapper import QlFsMapper
from .stats import QlOsStats
from .utils import QlOsUtils
from .path import QlOsPath

class QlOs:
    type: QL_OS

    Resolver = Callable[[int], Any]

    def __init__(self, ql: Qiling, resolvers: Mapping[Any, Resolver] = {}):
        self.ql = ql

        # standard streams overrides (elicn: should they be io.IOBase ?)
        self._stdin:  TextIO
        self._stdout: TextIO
        self._stderr: TextIO

        self.utils = QlOsUtils(ql)
        self.stats = QlOsStats()
        self.fcall: QlFunctionCall
        self.child_processes = False
        self.thread_management = None
        self.profile = self.ql.profile
        self.exit_code = 0

        if self.type in QL_OS_POSIX + (QL_OS.WINDOWS, QL_OS.DOS):
            cwd = self.profile.get("MISC", "current_path")

            self.path = QlOsPath(ql.rootfs, cwd, self.type)
            self.fs_mapper = QlFsMapper(self.path)

        self.user_defined_api = {
            QL_INTERCEPT.CALL : {},
            QL_INTERCEPT.ENTER: {},
            QL_INTERCEPT.EXIT : {}
        }

        # IDAPython has some hack on standard io streams and thus they don't have corresponding fds.
        try:
            import ida_idaapi
        except ImportError:
            self._stdin  = ql_file('stdin',  sys.stdin.fileno())
            self._stdout = ql_file('stdout', sys.stdout.fileno())
            self._stderr = ql_file('stderr', sys.stderr.fileno())
        else:
            self._stdin  = getattr(sys.stdin,  'buffer', sys.stdin)
            self._stdout = getattr(sys.stdout, 'buffer', sys.stdout)
            self._stderr = getattr(sys.stderr, 'buffer', sys.stderr)

        # defult exit point
        self.exit_point = {
            16: 0xfffff,            # 20bit address lane
            32: 0x8fffffff,
            64: 0xffffffffffffffff
        }.get(self.ql.arch.bits, None)

        if self.ql.code:
            # this shellcode entrypoint does not work for windows
            # windows shellcode entry point will comes from pe loader
            self.entry_point = self.profile.getint('CODE', 'entry_point')
            self.code_ram_size = self.profile.getint('CODE', 'ram_size')

        # default fcall paramters resolving methods
        self.resolvers = {
            STRING : lambda ptr: ptr and self.utils.read_cstring(ptr),
            WSTRING: lambda ptr: ptr and self.utils.read_wstring(ptr),
            GUID   : lambda ptr: ptr and str(self.utils.read_guid(ptr))
        }

        # let the user override default resolvers or add custom ones
        self.resolvers.update(resolvers)

    def save(self) -> Mapping[str, Any]:
        return {}

    def restore(self, saved_state: Mapping[str, Any]):
        pass

    @property
    def stdin(self) -> TextIO:
        """Program's standard input stream. May be replaced by any object that implements
        the `io.IOBase` interface, either fully or partially.
        """

        return self._stdin

    @property
    def stdout(self) -> TextIO:
        """Program's standard output stream. May be replaced by any object that implements
        the `io.IOBase` interface, either fully or partially.
        """

        return self._stdout

    @property
    def stderr(self) -> TextIO:
        """Program's standard error stream. May be replaced by any object that implements
        the `io.IOBase` interface, either fully or partially.
        """

        return self._stderr

    @stdin.setter
    def stdin(self, stream: TextIO) -> None:
        self._stdin = stream

    @stdout.setter
    def stdout(self, stream: TextIO) -> None:
        self._stdout = stream

    @stderr.setter
    def stderr(self, stream: TextIO) -> None:
        self._stderr = stream

    @property
    def root(self) -> bool:
        """An indication whether the process is running as root.
        """

        # for this to work the os derivative should override this property
        # and implement the os logic. in case it is not, return False
        return False

    @root.setter
    def root(self, enabled: bool) -> None:
        raise NotImplementedError('Running as root is not implemented for this OS')

    def resolve_fcall_params(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        """Transform function call raw parameters values into meaningful ones, according to
        their assigned type.

        Args:
            params: a mapping of parameter names to their types

        Returns: a mapping of parameter names to their resolved values
        """

        # TODO: could use func.__annotations__ to resolve parameters and return type.
        #       that would require redefining all hook functions with python annotations, but
        #       also simplify hooks code (e.g. no need to do:  x = params["x"] )

        names = params.keys()
        types = params.values()
        values = self.fcall.readParams(types)
        resolved = {}

        for name, typ, val in zip(names, types, values):
            if typ in self.resolvers:
                val = self.resolvers[typ](val)

            resolved[name] = val

        return resolved

    def process_fcall_params(self, targs: Iterable[TypedArg]) -> Sequence[Tuple[str, str]]:
        ahandlers: Mapping[type, Callable[[Any], str]] = {
            int       : lambda v: f'{v:#x}' if v else f'0',
            str       : lambda v: QlOsUtils.stringify(v),
            bytearray : lambda v: QlOsUtils.stringify(v.decode("utf-8")),
            tuple     : lambda v: QlOsUtils.stringify(v[1])
        }

        return tuple((aname, ahandlers[type(avalue)](avalue)) for atype, aname, avalue in targs)

    def call(self, pc: int, func: Callable, proto: Mapping[str, Any], onenter: Optional[Callable], onexit: Optional[Callable], passthru: bool = False):
        # resolve arguments values according to their types
        args = self.resolve_fcall_params(proto)

        # call hooked function
        targs, retval, retaddr = self.fcall.call(func, proto, args, onenter, onexit, passthru)

        # post-process arguments values
        pargs = self.process_fcall_params(targs)

        # print
        self.utils.print_function(pc, func.__name__, pargs, retval, passthru)

        # append syscall to list
        self.stats.log_api_call(pc, func.__name__, args, retval, retaddr)

        # [Windows and UEFI] if emulation has stopped, do not update the return address
        if hasattr(self, 'PE_RUN') and not self.PE_RUN:
            passthru = True

        if not passthru:
            self.ql.arch.regs.arch_pc = retaddr

        return retval

    def set_api(self, target: Hashable, handler: Callable, intercept: QL_INTERCEPT = QL_INTERCEPT.CALL):
        """Either hook or replace an OS API with a custom one.

        Args:
            target: target API identifier
            handler: function to call
            intercept:
                `QL_INTERCEPT.CALL` : run handler instead of the existing target implementation
                `QL_INTERCEPT.ENTER`: run handler before the target API is called
                `QL_INTERCEPT.EXIT` : run handler after the target API is called
        """

        self.user_defined_api[intercept][target] = handler

    # os main method; derivatives must implement one of their own
    def run(self) -> None:
        raise NotImplementedError

    def stop(self):
        if self.ql.multithread:
            self.thread_management.stop() 
        else:
            self.ql.emu_stop()

    def emu_error(self):
        self.ql.log.error(f'CPU Context:')
        for reg in self.ql.arch.regs.register_mapping:
            if isinstance(reg, str):
                self.ql.log.error(f'{reg}\t: {self.ql.arch.regs.read(reg):#x}')

        pc = self.ql.arch.regs.arch_pc

        try:
            data = self.ql.mem.read(pc, size=8)
        except UcError:
            pc_info = ' (unreachable)'
        else:
            self.ql.log.error('Hexdump:')
            self.ql.log.error(data.hex(' '))

            self.ql.log.error('Disassembly:')
            self.ql.arch.utils.disassembler(self.ql, pc, 64)

            containing_image = self.ql.loader.find_containing_image(pc)
            pc_info = f' ({containing_image.path} + {pc - containing_image.base:#x})' if containing_image else ''
        finally:
            self.ql.log.error(f'PC = {pc:#0{self.ql.arch.pointersize * 2 + 2}x}{pc_info}\n')

            self.ql.log.error(f'Memory map:')
            for info_line in self.ql.mem.get_formatted_mapinfo():
                self.ql.log.error(info_line)
