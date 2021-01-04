#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import logging
from typing import Sequence
from pefile import PE

from qiling.const import QL_ARCH
from qiling.loader.loader import QlLoader
from qiling.os.memory import QlMemoryHeap
from qiling.os.utils import QlErrorArch, QlErrorFileType

from qiling.os.uefi import context, st, smst
from qiling.os.uefi.ProcessorBind import CPU_STACK_ALIGNMENT
from qiling.os.uefi.shutdown import hook_EndOfExecution
from qiling.os.uefi.protocols import EfiLoadedImageProtocol
from qiling.os.uefi.protocols import EfiSmmAccess2Protocol
from qiling.os.uefi.protocols import EfiSmmBase2Protocol
from qiling.os.uefi.protocols import EfiSmmCpuProtocol
from qiling.os.uefi.protocols import EfiSmmSwDispatch2Protocol
from qiling.os.uefi.protocols import PcdProtocol

class QlLoaderPE_UEFI(QlLoader):
    def __init__(self, ql):
        super(QlLoaderPE_UEFI, self).__init__(ql)
        self.ql = ql
        self.modules = []
        self.events = {}
        self.notify_list = []
        self.next_image_base = 0x10000

    def save(self):
        saved_state = super(QlLoaderPE_UEFI, self).save()

        saved_state['modules'] = self.modules
        saved_state['events'] = self.events
        #saved_state['handle_dict'] = self.handle_dict
        saved_state['notify_list'] = self.notify_list
        saved_state['next_image_base'] = self.next_image_base
        saved_state['loaded_image_protocol_modules'] = self.loaded_image_protocol_modules
        saved_state['tpl'] = self.tpl
        saved_state['efi_configuration_table'] = self.efi_configuration_table
        # since this class initialize the heap (that is hosted by the OS object), we will store it here.
        saved_state['heap'] = self.ql.os.heap.save()
        return saved_state

    def restore(self, saved_state):
        super(QlLoaderPE_UEFI, self).restore(saved_state)

        self.modules = saved_state['modules']
        self.events = saved_state['events']
        #self.handle_dict = saved_state['handle_dict']
        self.notify_list = saved_state['notify_list']
        self.next_image_base = saved_state['next_image_base']
        self.loaded_image_protocol_modules = saved_state['loaded_image_protocol_modules']
        self.tpl = saved_state['tpl']
        self.efi_configuration_table = saved_state['efi_configuration_table']
        self.ql.os.heap.restore(saved_state['heap'])

    def install_loaded_image_protocol(self, image_base, image_size):
        fields = {
            'gST'        : self.gST,
            'image_base' : image_base,
            'image_size' : image_size
        }

        descriptor = EfiLoadedImageProtocol.make_descriptor(fields)
        self.dxe_context.install_protocol(descriptor, image_base)

        self.loaded_image_protocol_modules.append(image_base)

    def map_and_load(self, path, execute_now=False):
        ql = self.ql
        pe = PE(path, fast_load=True)

        # Make sure no module will occupy the NULL page
        if self.next_image_base > pe.OPTIONAL_HEADER.ImageBase:
            IMAGE_BASE = self.next_image_base
            pe.relocate_image(IMAGE_BASE)
        else:
            IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
        IMAGE_SIZE = ql.mem.align(pe.OPTIONAL_HEADER.SizeOfImage, 0x1000)

        while IMAGE_BASE + IMAGE_SIZE < self.heap_base_address:
            if not ql.mem.is_mapped(IMAGE_BASE, 1):
                self.next_image_base = IMAGE_BASE + 0x10000
                ql.mem.map(IMAGE_BASE, IMAGE_SIZE)
                pe.parse_data_directories()
                data = bytearray(pe.get_memory_mapped_image())
                ql.mem.write(IMAGE_BASE, bytes(data))
                logging.info("[+] Loading %s to 0x%x" % (path, IMAGE_BASE))
                entry_point = IMAGE_BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint
                if self.entry_point == 0:
                    # Setting entry point to the first loaded module entry point, so the debugger can break.
                    self.entry_point = entry_point
    def call_function(self, addr: int, args: Sequence[int], eoe: int):
        """Call a function after properly setting up its arguments and return address.

        Args:
            addr : function address
            args : a sequence of arguments to pass to the function; may be empty
            eoe  : end-of-execution trap address; must be already hooked
                    """

        # arguments gpr (ms x64 cc)
        regs = ('rcx', 'rdx', 'r8', 'r9')
        assert len(args) <= len(regs), f'currently supporting up to {len(regs)} arguments'

        # set up the arguments
        for reg, arg in zip(regs, args):
            self.ql.reg.write(reg, arg)

        # mimic call instruction
        self.ql.stack_push(eoe)
        self.ql.reg.rip = addr
    def unload_modules(self):
        for handle in self.loaded_image_protocol_modules:
            struct_addr = self.dxe_context.protocols[handle][self.loaded_image_protocol_guid]
            loaded_image_protocol = EfiLoadedImageProtocol.EFI_LOADED_IMAGE_PROTOCOL.loadFrom(self.ql, struct_addr)

            unload_ptr = self.ql.unpack64(loaded_image_protocol.Unload)

            if unload_ptr != 0:
                self.call_function(unload_ptr, [handle], self.end_of_execution_ptr)
                self.loaded_image_protocol_modules.remove(handle)

                logging.info(f'Unloading module {handle:#x}, calling {unload_ptr:#x}')

                return True

        return False

    def execute_module(self, path: str, image_base: int, entry_point: int, eoe_trap: int):
        """Start the execution of a UEFI module.

        Args:
            image_base  : module base address
            entry_point : module entry point address
            eoe_trap    : end-of-execution trap address
        """

        # use familiar UEFI names
        ImageHandle = image_base
        SystemTable = self.gST

        self.call_function(entry_point, [ImageHandle, SystemTable], eoe_trap)
        self.ql.os.entry_point = entry_point

        logging.info(f'Running from {entry_point:#010x} of {path}')

    def execute_next_module(self):
        if not self.modules or self.ql.os.notify_before_module_execution(self.ql, self.modules[0][0]):
            return

        path, image_base, entry_point = self.modules.pop(0)
        self.execute_module(path, image_base, entry_point, self.end_of_execution_ptr)

    def run(self):
        # intel architecture uefi implementaion only
        if self.ql.archtype not in (QL_ARCH.X86, QL_ARCH.X8664):
            raise QlErrorArch("[!] Unsupported architecture")

        # x86-64 arch only
        if self.ql.archtype != QL_ARCH.X8664:
            raise QlErrorArch("[!] Only 64 bit arch is supported at the moment")

        self.loaded_image_protocol_guid = self.ql.os.profile["LOADED_IMAGE_PROTOCOL"]["guid"]
        self.loaded_image_protocol_modules = []
        self.tpl = 4 # TPL_APPLICATION

        self.user_defined_api = self.ql.os.user_defined_api
        self.user_defined_api_onenter = self.ql.os.user_defined_api_onenter
        self.user_defined_api_onexit = self.ql.os.user_defined_api_onexit

        arch_key = {
            QL_ARCH.X86   : "OS32",
            QL_ARCH.X8664 : "OS64"
        }[self.ql.archtype]

        # -------- init BS / RT / DXE data structures and protocols --------

        os_profile = self.ql.os.profile[arch_key]
        self.dxe_context = context.UefiContext(self.ql)

        # initialize and locate heap
        heap_base = int(os_profile["heap_address"], 0)
        heap_size = int(os_profile["heap_size"], 0)
        self.dxe_context.init_heap(heap_base, heap_size)
        self.heap_base_address = heap_base
        logging.info(f"[+] Located heap at {heap_base:#010x}")

        # initialize and locate stack
        stack_base = int(os_profile["stack_address"], 0)
        stack_size = int(os_profile["stack_size"], 0)
        self.dxe_context.init_stack(stack_base, stack_size)
        sp = stack_base + stack_size - CPU_STACK_ALIGNMENT
        logging.info(f"[+] Located stack at {sp:#010x}")

        # TODO: statically allocating 256 KiB for ST, RT, BS, DS and Configuration Tables.
        # however, this amount of memory is rather arbitrary
        gST = self.dxe_context.heap.alloc(256 * 1024)
        st.initialize(self.ql, gST)

        protocols = (
            EfiSmmAccess2Protocol,
            EfiSmmBase2Protocol,
            PcdProtocol
        )

        for proto in protocols:
            self.dxe_context.install_protocol(proto.descriptor, 1)

        # workaround
        self.ql.os.heap = self.dxe_context.heap

        # -------- init SMM data structures and protocols --------

        smm_profile = self.ql.os.profile['SMRAM']
        self.smm_context = context.SmmContext(self.ql)

        # initialize and locate SMM heap
        heap_base = int(smm_profile["heap_address"], 0)
        heap_size = int(smm_profile["heap_size"], 0)
        self.smm_context.init_heap(heap_base, heap_size)
        logging.info(f"[+] Located SMM heap at {heap_base:#010x}")

        # TODO: statically allocating 256 KiB for SMM ST.
        # however, this amount of memory is rather arbitrary
        gSmst = self.smm_context.heap.alloc(256 * 1024)
        smst.initialize(self.ql, gSmst)

        self.gST = gST
        self.gSmst = gSmst
        self.in_smm = False

        protocols = (
            EfiSmmCpuProtocol,
            EfiSmmSwDispatch2Protocol
        )

        for proto in protocols:
            self.smm_context.install_protocol(proto.descriptor, 1)

        # map mmio ranges
        # TODO: move to somehwere more appropriate (+ hook accesses?)
        mmio_map = self.ql.os.profile["MMIO"]
        self.ql.mem.map(
            int(mmio_map['sbreg_base'], 0),
            int(mmio_map['sbreg_size'], 0)
        )

        # set stack and frame pointers
        self.ql.reg.rsp = sp
        self.ql.reg.rbp = sp

        self.entry_point = 0
        self.load_address = 0
        self.next_image_base = int(os_profile["image_address"], 0)

        for dependency in self.ql.argv:
            if not self.map_and_load(dependency):
                raise QlErrorFileType("Can't map dependency")

        logging.info(f"[+] Done with loading {self.ql.path}")

        # set up an end-of-execution hook to regain control when module is done
        # executing (i.e. when the entry point function returns). that should be
        # set on a non-executable address, so SystemTable's address was picked
        self.end_of_execution_ptr = gST
        self.ql.hook_address(hook_EndOfExecution, self.end_of_execution_ptr)

        self.execute_next_module()

    def restore_runtime_services(self):
        pass # not sure why do we need to restore RT
