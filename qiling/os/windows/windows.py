#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ntpath
from typing import Callable, TextIO, Type

from unicorn import UcError

from qiling import Qiling
from qiling.arch.x86_const import GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE
from qiling.arch.x86_utils import GDTManager, SegmentManager, SegmentManager86, SegmentManager64
from qiling.cc import intel
from qiling.const import QL_ARCH, QL_OS, QL_INTERCEPT
from qiling.exception import QlErrorSyscallError, QlErrorSyscallNotFound, QlMemoryMappedError
from qiling.os.fcall import QlFunctionCall
from qiling.os.memory import QlMemoryHeap
from qiling.os.os import QlOs
from qiling.os.stats import QlWinStats

from . import const
from . import fncc
from . import handle
from . import thread
from . import clipboard
from . import fiber
from . import registry

import qiling.os.windows.dlls as api

class QlOsWindows(QlOs):
    type = QL_OS.WINDOWS

    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.ql = ql

        def __make_fcall_selector(atype: QL_ARCH) -> Callable[[int], QlFunctionCall]:
            """ [internal] Generate a fcall selection function based on the required calling
            convention. This is unique to 32-bits Windows, which may need to call both CDECL
            and STDCALL functions. The 64-bits version, on the other hand, always use MS64.

            To maintain the same behavior across Windows versions, the fcall selection function
            for 64-bit is designed to ignore the calling convention identifier and always return
            a MS64 fcall instance.
            """

            __fcall_objs = {
                fncc.STDCALL: QlFunctionCall(ql, intel.stdcall(ql.arch)),
                fncc.CDECL  : QlFunctionCall(ql, intel.cdecl(ql.arch)),
                fncc.MS64   : QlFunctionCall(ql, intel.ms64(ql.arch))
            }

            __selector = {
                QL_ARCH.X86  : lambda cc: __fcall_objs[cc],
                QL_ARCH.X8664: lambda cc: __fcall_objs[fncc.MS64]
            }

            return __selector[atype]

        self.fcall_select = __make_fcall_selector(ql.arch.type)
        self.fcall = self.fcall_select(fncc.CDECL)

        self.stats = QlWinStats()

        ossection = f'OS{self.ql.arch.bits}'
        heap_base = self.profile.getint(ossection, 'heap_address')
        heap_size = self.profile.getint(ossection, 'heap_size')

        self.heap = QlMemoryHeap(self.ql, heap_base, heap_base + heap_size)

        sysdrv = self.profile.get('PATH', 'systemdrive')
        windir = self.profile.get('PATH', 'windir')
        username = self.profile.get('USER', 'username')

        self.windir = ntpath.join(sysdrv, windir)
        self.winsys = ntpath.join(sysdrv, windir, 'System32')
        self.userprofile = ntpath.join(sysdrv, 'Users', username)
        self.username = username

        self.PE_RUN = False
        self.last_error = 0
        # variables used inside hooks
        self.hooks_variables = {}
        self.syscall_count = {}
        self.argv = self.ql.argv
        self.env = self.ql.env
        self.pid = self.profile.getint('KERNEL', 'pid')

        self.services = {}
        self.load()

        # only after handle manager has been set up we can assign the standard streams
        self.stdin  = self._stdin
        self.stdout = self._stdout
        self.stderr = self._stderr


    @QlOs.stdin.setter
    def stdin(self, stream: TextIO) -> None:
        self._stdin = stream

        handle = self.handle_manager.get(const.STD_INPUT_HANDLE)
        assert handle is not None

        handle.obj = stream

    @QlOs.stdout.setter
    def stdout(self, stream: TextIO) -> None:
        self._stdout = stream

        handle = self.handle_manager.get(const.STD_OUTPUT_HANDLE)
        assert handle is not None

        handle.obj = stream

    @QlOs.stderr.setter
    def stderr(self, stream: TextIO) -> None:
        self._stderr = stream

        handle = self.handle_manager.get(const.STD_ERROR_HANDLE)
        assert handle is not None

        handle.obj = stream


    def load(self):
        self.setupGDT()
        self.__setup_components()

        # hook win api
        self.ql.hook_code(self.hook_winapi)


    def setupGDT(self):
        gdtm = GDTManager(self.ql)

        segm_class: Type[SegmentManager] = {
            32 : SegmentManager86,
            64 : SegmentManager64
        }[self.ql.arch.bits]

        # setup gdt and segments selectors
        segm = segm_class(self.ql.arch, gdtm)
        segm.setup_cs_ds_ss_es(0, 4 << 30)
        segm.setup_fs(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE)
        segm.setup_gs(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE)

        if not self.ql.mem.is_available(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE):
            raise QlMemoryMappedError('cannot map FS segment, memory location is taken')

        self.ql.mem.map(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE, info='[FS]')

        if not self.ql.mem.is_available(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE):
            raise QlMemoryMappedError('cannot map GS segment, memory location is taken')

        self.ql.mem.map(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, info='[GS]')


    def __setup_components(self):
        reghive = self.path.transform_to_real_path(ntpath.join(self.windir, 'registry'))

        self.handle_manager = handle.HandleManager()
        self.registry_manager = registry.RegistryManager(self.ql, reghive)
        self.clipboard = clipboard.Clipboard(self)
        self.fiber_manager = fiber.FiberManager(self.ql)

        main_thread = thread.QlWindowsThread(self.ql)
        self.thread_manager = thread.QlWindowsThreadManagement(self.ql, self, main_thread)

        # more handle manager
        new_handle = handle.Handle(obj=main_thread)
        self.handle_manager.append(new_handle)

    # hook WinAPI in PE EMU
    def hook_winapi(self, ql: Qiling, address: int, size: int):
        if address in ql.loader.import_symbols:
            entry = ql.loader.import_symbols[address]
            api_name = entry['name']

            if api_name is None:
                api_name = const.Mapper[entry['dll']][entry['ordinal']]
            else:
                api_name = api_name.decode()

            api_func = self.user_defined_api[QL_INTERCEPT.CALL].get(api_name)

            if not api_func:
                api_func = getattr(api, f'hook_{api_name}', None)

            if api_func:
                self.syscall_count.setdefault(api_name, 0)
                self.syscall_count[api_name] += 1

                try:
                    api_func(ql, address, api_name)
                except Exception as ex:
                    ql.log.exception(ex)
                    ql.log.debug("%s Exception Found" % api_name)

                    raise QlErrorSyscallError("Windows API Implementation Error")
            else:
                ql.log.warning(f'api {api_name} ({entry["dll"]}) is not implemented')

                if ql.debug_stop:
                    raise QlErrorSyscallNotFound("Windows API implementation not found")


    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        if  self.ql.entry_point is not None:
            self.ql.loader.entry_point = self.ql.entry_point

        entry_point = self.ql.loader.entry_point
        exit_point = (self.ql.loader.entry_point + len(self.ql.code)) if self.ql.code else self.exit_point

        self.PE_RUN = True

        try:
            self.ql.emu_start(entry_point, exit_point, self.ql.timeout, self.ql.count)
        except UcError:
            self.emu_error()
            raise

        self.registry_manager.save()

        # display summary
        for entry in self.stats.summary():
            self.ql.log.debug(entry)
