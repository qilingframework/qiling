#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import json
import ntpath
from typing import Callable

from unicorn import UcError

from qiling import Qiling
from qiling.arch.x86_const import GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE
from qiling.arch.x86_utils import GDTManager, SegmentManager86, SegmentManager64
from qiling.cc import intel
from qiling.const import QL_ARCH, QL_INTERCEPT
from qiling.exception import QlErrorSyscallError, QlErrorSyscallNotFound
from qiling.os.fcall import QlFunctionCall
from qiling.os.memory import QlMemoryHeap
from qiling.os.os import QlOs

from . import const
from . import fncc
from . import handle
from . import thread
from . import clipboard
from . import fiber
from . import registry

import qiling.os.windows.dlls as api

class QlOsWindows(QlOs):
    def __init__(self, ql: Qiling):
        super(QlOsWindows, self).__init__(ql)

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

        ossection = f'OS{self.ql.arch.bits}'
        heap_base = self.profile.getint(ossection, 'heap_address')
        heap_size = self.profile.getint(ossection, 'heap_size')

        self.heap = QlMemoryHeap(self.ql, heap_base, heap_base + heap_size)

        sysdrv = self.profile.get('PATH', 'systemdrive')
        windir = self.profile.get('PATH', 'windir')
        username = self.profile.get('USER', 'username')

        self.windir = ntpath.join(sysdrv, windir)
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
        self.automatize_input = self.profile.getboolean("MISC","automatize_input")

        self.services = {}
        self.load()


    def load(self):
        self.setupGDT()
        self.setupComponents()

        # hook win api
        self.ql.hook_code(self.hook_winapi)


    def setupGDT(self):
        gdtm = GDTManager(self.ql)

        segm_class = {
            32 : SegmentManager86,
            64 : SegmentManager64
        }[self.ql.arch.bits]

        # setup gdt and segments selectors
        segm = segm_class(self.ql.arch, gdtm)
        segm.setup_cs_ds_ss_es(0, 4 << 30)
        segm.setup_fs(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE)
        segm.setup_gs(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE)

        if not self.ql.mem.is_mapped(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE):
            self.ql.mem.map(FS_SEGMENT_ADDR, FS_SEGMENT_SIZE, info='[FS]')

        if not self.ql.mem.is_mapped(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE):
            self.ql.mem.map(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, info='[GS]')


    def setupComponents(self):
        # handle manager
        self.handle_manager = handle.HandleManager()
        # registry manger
        self.registry_manager = registry.RegistryManager(self.ql)
        # clipboard
        self.clipboard = clipboard.Clipboard(self)
        # fibers
        self.fiber_manager = fiber.FiberManager(self.ql)
        # thread manager
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


    def post_report(self):
        self.ql.log.debug("Syscalls called:")
        for key, values in self.stats.syscalls.items():
            self.ql.log.debug(f'{key}:')

            for value in values:
                self.ql.log.debug(f'  {json.dumps(value):s}')

        self.ql.log.debug("Registries accessed:")
        for key, values in self.registry_manager.accessed.items():
            self.ql.log.debug(f'{key}:')

            for value in values:
                self.ql.log.debug(f'  {json.dumps(value):s}')

        self.ql.log.debug("Strings:")
        for key, values in self.stats.appeared_strings.items():
            self.ql.log.debug(f'{key}: {" ".join(str(word) for word in values)}')


    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        if  self.ql.entry_point is not None:
            self.ql.loader.entry_point = self.ql.entry_point

        self.PE_RUN = True

        try:
            if self.ql.code:
                self.ql.emu_start(self.ql.loader.entry_point, (self.ql.loader.entry_point + len(self.ql.code)), self.ql.timeout, self.ql.count)
            else:
                self.ql.emu_start(self.ql.loader.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
        except UcError:
            self.emu_error()
            raise

        self.registry_manager.save()
        self.post_report()
