#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
from typing import Any, Iterable, Optional, Callable, Mapping, Sequence, TextIO, Tuple

from unicorn import UcError

from qiling import Qiling
from qiling.const import QL_OS, QL_INTERCEPT, QL_OS_POSIX
from qiling.os.const import STRING, WSTRING, GUID
from qiling.os.fcall import QlFunctionCall

from .filestruct import ql_file
from .mapper import QlFsMapper
from .utils import QlOsUtils
from .path import QlPathManager

class QlOs:
    Resolver = Callable[[int], Any]

    def __init__(self, ql: Qiling, resolvers: Mapping[Any, Resolver] = {}):
        self.ql = ql

        # standard streams overrides (elicn: should they be io.IOBase ?)
        self._stdin:  TextIO
        self._stdout: TextIO
        self._stderr: TextIO

        self.utils = QlOsUtils(ql)
        self.fcall: QlFunctionCall
        self.fs_mapper = QlFsMapper(ql)
        self.child_processes = False
        self.thread_management = None
        self.profile = self.ql.profile
        self.path = QlPathManager(ql, self.ql.profile.get("MISC", "current_path"))
        self.exit_code = 0

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
        }.get(self.ql.archbit, None)

        if self.ql.code:
            self.code_ram_size = int(self.profile.get("CODE", "ram_size"), 16)
            # this shellcode entrypoint does not work for windows
            # windows shellcode entry point will comes from pe loader
            self.entry_point = int(self.profile.get("CODE", "entry_point"), 16)

        # default fcall paramters resolving methods
        self.resolvers = {
            STRING : lambda ptr: ptr and self.utils.read_cstring(ptr),
            WSTRING: lambda ptr: ptr and self.utils.read_wstring(ptr),
            GUID   : lambda ptr: ptr and str(self.utils.read_guid(ptr))
        }

        # let the user override default resolvers or add custom ones
        self.resolvers.update(resolvers)

        self.ql.arch.utils.setup_output()

    def save(self):
        return {}

    def restore(self, saved_state):
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

    def process_fcall_params(self, targs: Iterable[Tuple[Any, str, Any]]) -> Sequence[Tuple[str, str]]:
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
        self.utils._call_api(pc, func.__name__, args, retval, retaddr)

        # [Windows and UEFI] if emulation has stopped, do not update the return address
        if hasattr(self, 'PE_RUN') and not self.PE_RUN:
            passthru = True

        if not passthru:
            self.ql.reg.arch_pc = retaddr

        return retval

    # TODO: separate this method into os-specific functionalities, instead of 'if-else'
    def set_api(self, api_name: str, intercept_function: Callable, intercept: QL_INTERCEPT):
        if self.ql.ostype == QL_OS.UEFI:
            api_name = f'hook_{api_name}'

        # BUG: workaround missing arg
        if intercept is None:
            intercept = QL_INTERCEPT.CALL

        if (self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI, QL_OS.DOS)) or (self.ql.ostype in (QL_OS_POSIX) and self.ql.loader.is_driver):
            self.user_defined_api[intercept][api_name] = intercept_function
        else:
            self.add_function_hook(api_name, intercept_function, intercept)

    def find_containing_image(self, pc):
        for image in self.ql.loader.images:
            if image.base <= pc < image.end:
                return image

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
        for reg in self.ql.reg.register_mapping:
            if isinstance(reg, str):
                self.ql.log.error(f'{reg}\t: {self.ql.reg.read(reg):#x}')

        pc = self.ql.reg.arch_pc

        try:
            data = self.ql.mem.read(pc, size=8)
        except UcError:
            pc_info = ' (unreachable)'
        else:
            self.ql.log.error('Hexdump:')
            self.ql.log.error(data.hex(' '))

            self.ql.log.error('Disassembly:')
            self.ql.arch.utils.disassembler(self.ql, pc, 64)

            containing_image = self.find_containing_image(pc)
            pc_info = f' ({containing_image.path} + {pc - containing_image.base:#x})' if containing_image else ''
        finally:
            self.ql.log.error(f'PC = {pc:#0{self.ql.pointersize * 2 + 2}x}{pc_info}\n')

            self.ql.log.info(f'Memory map:')
            self.ql.mem.show_mapinfo()
