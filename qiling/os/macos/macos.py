#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import traceback

from unicorn import *
from unicorn.x86_const import *
from unicorn.arm64_const import *

from qiling.arch.x86 import *

from qiling.const import *
from qiling.os.const import *
from qiling.os.posix.posix import QlOsPosix

from .const import *

from qiling.os.macos import macos
from qiling.os.macos.structs import *
from qiling.os.macos.events.macos_structs import *
from qiling.os.macos.events.macos import *
from qiling.os.macos.events.macos_policy import *

class QlOsMacos(QlOsPosix):
    def __init__(self, ql):
        super(QlOsMacos, self).__init__(ql)
        self.ql = ql
        self.ql.counter = 0
        self.user_defined_api = {}
        self.ev_manager = QlMacOSEvManager(self.ql)
        self.policy_manager = QlMacOSPolicy(self.ql, self.ev_manager)
        self.RUN = True
        self.hook_ret = {}
        self.pid = self.profile.getint("KERNEL","pid")
        self.load()

    # load MacOS driver
    def load_kext(self):
        from qiling.os.macos.events.macos_structs import mac_policy_list_t
        from qiling.os.macos.structs import list_head
        self.heap.clear()

        # Setup mac_policy_list
        kern_mac_policy_list = self.ql.loader.kernel_extrn_symbols_detail[b"_mac_policy_list"]["n_value"]
        mac_policy_list_addr = self.heap.alloc(ctypes.sizeof(mac_policy_list_t))
        self.mac_policy_list = mac_policy_list_t(self, mac_policy_list_addr)
        self.ql.mem.write(kern_mac_policy_list, struct.pack("<Q", mac_policy_list_addr))

        # Add initial process to allproc in kernel
        allproc = self.ql.loader.kernel_extrn_symbols_detail[b"_allproc"]["n_value"]
        self.ev_manager.set_allproc(allproc)
        self.ev_manager.add_process(0, "head")
        self.ev_manager.add_process(0x1337, "demigod")
        self.ev_manager.add_process(1, "tail")

        if self.ql.loader.IOKit is True: # Handle IOKit driver
            self.ql.stack_push(0)
            self.savedrip=0xffffff8000a163bd
            self.ql.run(begin=self.ql.loader.kext_alloc)
            self.kext_object = self.ql.reg.rax
            self.ql.dprint(D_INFO, "[+] Created kext object at 0x%x" % self.kext_object)

            self.ql.reg.rdi = self.kext_object
            self.ql.reg.rsi = 0 # NULL option
            self.savedrip=0xffffff8000a16020
            self.ql.run(begin=self.ql.loader.kext_init)
            if self.ql.reg.rax == 0:
                self.ql.dprint(D_INFO, "[!] Failed to initialize kext object")
                return
            self.ql.dprint(D_INFO, "[+] Initialized kext object")

            self.ql.reg.rdi = self.kext_object
            # FIXME Determine provider for kext
            self.ql.reg.rsi = 0 # ?
            self.savedrip=0xffffff8000a16102
            self.ql.run(begin=self.ql.loader.kext_attach)
            if self.ql.reg.rax == 0:
                self.ql.dprint(D_INFO, "[!] Failed to attach kext object")
                return
            self.ql.dprint(D_INFO, "[+] Attached kext object 1st time")

            self.ql.reg.rdi = self.kext_object
            self.ql.reg.rdi = 0
            # FIXME Determine provider for kext
            self.ql.reg.rsi = 0 # ?
            tmp = self.heap.alloc(8)
            self.ql.reg.rdx = tmp
            self.savedrip=0xffffff8000a16184
            self.ql.run(begin=self.ql.loader.kext_probe)
            self.heap.free(tmp)
            self.ql.dprint(D_INFO, "[+] Probed kext object")

            self.ql.reg.rdi = self.kext_object
            # FIXME Determine provider for kext
            self.ql.reg.rsi = 0 # ?
            self.savedrip=0xffffff8000a16198
            self.ql.run(begin=self.ql.loader.kext_detach)
            self.ql.dprint(D_INFO, "[+] Detached kext object")

            self.ql.reg.rdi = self.kext_object
            # FIXME Determine provider for kext
            self.ql.reg.rsi = 0 # ?
            self.savedrip=0xffffff8000a168a3
            self.ql.run(begin=self.ql.loader.kext_attach)
            if self.ql.reg.rax == 0:
                self.ql.dprint(D_INFO, "[!] Failed to attach kext object")
                return
            self.ql.dprint(D_INFO, "[+] Attached kext object 2nd time")

            self.ql.reg.rdi = self.kext_object
            # FIXME Determine provider for kext
            self.ql.reg.rsi = 0 # ?
            self.savedrip=0xffffff8000a168ed
            self.ql.run(begin=self.ql.loader.kext_start)
        else:
            from qiling.os.macos.structs import kmod_info_t, POINTER64
            kmod_info_addr = self.heap.alloc(ctypes.sizeof(kmod_info_t))
            self.ql.dprint(D_INFO, "[+] Created fake kmod_info at 0x%x" % kmod_info_addr)
            kmod_info = kmod_info_t(self.ql, kmod_info_addr)

            # OSKext.cpp:562
            kmod_info.next = POINTER64(0)
            kmod_info.info_version = 1
            kmod_info.id = 1
            kmod_info.name = self.ql.loader.plist["CFBundleIdentifier"].encode()
            kmod_info.version = self.ql.loader.plist["CFBundleVersion"].encode()
            kmod_info.reference_count = 0
            kmod_info.reference_list = POINTER64(0)
            kmod_info.address = POINTER64(self.ql.loader.slide)
            kmod_info.size = self.ql.loader.kext_size
            kmod_info.hdr_size = self.ql.loader.macho_file.header.header_size
            kmod_info.start = POINTER64(self.ql.loader.kext_start)
            kmod_info.stop = POINTER64(self.ql.loader.kext_stop)

            kmod_info.updateToMem()
            self.ql.dprint(D_INFO, "[+] Initialized kmod_info")

            self.ql.reg.rdi = kmod_info_addr
            self.ql.reg.rsi = 0
            self.savedrip=0xffffff80009c2c16
            self.ql.run(begin=self.ql.loader.kext_start)

    def load(self):
        if self.ql.shellcoder:
            return

        if self.ql.archtype== QL_ARCH.ARM64:
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)
            self.ql.hook_intno(self.hook_sigtrap, 7)

        elif self.ql.archtype== QL_ARCH.X8664:
            self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)

    
    def hook_syscall(self, intno= None, int = None):
        return self.load_syscall()

    def hook_sigtrap(self, intno= None, int = None):
        self.ql.nprint("[!] Trap Found")
        self.emu_error()
        exit(1)

    def run(self):
        #save initial stack pointer, so we can see if stack is balanced when
        #this function return at the end
        if self.ql.loader.kext_name and self.savedrip is not None:
            """
            Use following code to extract saved rip from method:
            {
                ...
                unsigned long rbp_register;
                __asm__ volatile ("mov %%rbp, %0" : "=r" (rbp_register));
                unsigned char *saved_rip = (unsigned char *) (*(unsigned long *)(rbp_register + sizeof(void *)));
                ...
            }
            """
            self.ql.stack_push(self.savedrip)
            def callback_ret(ql):
                ql.reg.arch_pc = 0
                
            if self.savedrip not in self.hook_ret:
                tmp = self.ql.hook_address(callback_ret, self.savedrip)
                self.hook_ret[self.savedrip] = tmp
        elif self.ql.loader.kext_name:
            self.ql.stack_push(0)

        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        if  self.ql.entry_point is not None:
                self.ql.loader.entry_point = self.ql.entry_point    

        try:
            if self.ql.shellcoder:
                self.ql.emu_start(self.entry_point, (self.entry_point + len(self.ql.shellcoder)), self.ql.timeout, self.ql.count)
            
            else:
                self.ql.emu_start(self.ql.loader.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
        except UcError:
            self.RUN = False

            # TODO: This is for kext, we need to fix it later
            if self.ql.output != QL_OUTPUT.DEBUG:
                return
            
            self.emu_error()
            raise

        self.RUN = False

        if self.ql.internal_exception != None:
            raise self.ql.internal_exception