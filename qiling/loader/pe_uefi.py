#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Optional, Sequence
from pefile import PE

from qiling import Qiling
from qiling.const import QL_ARCH
from qiling.exception import QlErrorArch, QlMemoryMappedError
from qiling.loader.loader import QlLoader, Image

from qiling.os.uefi import context, st, smst
from qiling.os.uefi.ProcessorBind import CPU_STACK_ALIGNMENT
from qiling.os.uefi.shutdown import hook_EndOfExecution
from qiling.os.uefi.protocols import EfiLoadedImageProtocol
from qiling.os.uefi.protocols import EfiSmmAccess2Protocol
from qiling.os.uefi.protocols import EfiSmmBase2Protocol
from qiling.os.uefi.protocols import EfiSmmCpuProtocol
from qiling.os.uefi.protocols import EfiSmmSwDispatch2Protocol

class QlLoaderPE_UEFI(QlLoader):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.ql = ql
        self.modules = []
        self.events = {}
        self.notify_list = []
        self.next_image_base = 0

    # list of members names to save and restore
    __save_members = (
        'modules',
        'events',
        'notify_list',
        'next_image_base',
        'loaded_image_protocol_modules',
        'tpl',
        'efi_conf_table_array',
        'efi_conf_table_array_ptr',
        'efi_conf_table_data_ptr',
        'efi_conf_table_data_next_ptr'
    )

    def save(self) -> dict:
        saved_state = super(QlLoaderPE_UEFI, self).save()

        for member in QlLoaderPE_UEFI.__save_members:
            saved_state[member] = getattr(self, member)

        # since this class initialize the heap (that is hosted by the OS object), we will store it here
        saved_state['heap'] = self.ql.os.heap.save()

        return saved_state

    def restore(self, saved_state: dict):
        super(QlLoaderPE_UEFI, self).restore(saved_state)

        for member in QlLoaderPE_UEFI.__save_members:
            setattr(self, member, saved_state[member])

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

    def map_and_load(self, path: str, exec_now: bool=False):
        """Map and load a module into memory.

        The specified module would be mapped and loaded into the address set
        in the `next_image_base` member. It is the caller's responsibility to
        make sure that the memory is available.

        On success, `next_image_base` will be updated accordingly.

        Args:
            path     : path of the module binary to load
            exec_now : execute module right away; will be enququed if not

        Raises:
            QlMemoryMappedError : when `next_image_base` is not available
        """

        ql = self.ql
        pe = PE(path, fast_load=True)

        # use image base only if it does not point to NULL
        image_base = pe.OPTIONAL_HEADER.ImageBase or self.next_image_base
        image_size = ql.mem.align(pe.OPTIONAL_HEADER.SizeOfImage, 0x1000)

        assert (image_base % 0x1000) == 0, 'image base is expected to be page-aligned'

        if image_base != pe.OPTIONAL_HEADER.ImageBase:
            pe.relocate_image(image_base)

        pe.parse_data_directories()
        data = bytes(pe.get_memory_mapped_image())

        ql.mem.map(image_base, image_size, info="[module]")
        ql.mem.write(image_base, data)
        ql.log.info(f'Module {path} loaded to {image_base:#x}')

        entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ql.log.info(f'Module entry point at {entry_point:#x}')

        # the 'entry_point' member is used by the debugger. if not set, set it
        # to the first loaded module entry point so the debugger can break
        if self.entry_point == 0:
            self.entry_point = entry_point

        self.install_loaded_image_protocol(image_base, image_size)

        # this would be used later be os.find_containing_image
        self.images.append(Image(image_base, image_base + image_size, path))

        # update next memory slot to allow sequencial loading. its availability
        # is unknown though
        self.next_image_base = image_base + image_size

        module_info = (path, image_base, entry_point)

        # execute the module right away or enqueue it
        if exec_now:
            # call entry point while retaining the current return address
            self.execute_module(*module_info, eoe_trap=None)
        else:
            self.modules.append(module_info)

    def call_function(self, addr: int, args: Sequence[int], ret: Optional[int]):
        """Call a function after properly setting up its arguments and return address.

        Args:
            addr : function address
            args : a sequence of arguments to pass to the function; may be empty
            ret  : return address; may be None
        """

        # arguments gpr (ms x64 cc)
        regs = ('rcx', 'rdx', 'r8', 'r9')
        assert len(args) <= len(regs), f'currently supporting up to {len(regs)} arguments'

        # set up the arguments
        for reg, arg in zip(regs, args):
            self.ql.reg.write(reg, arg)

        # if provided, set return address
        if ret is not None:
            self.ql.stack_push(ret)

        self.ql.reg.rip = addr

    def unload_modules(self):
        for handle in self.loaded_image_protocol_modules:
            struct_addr = self.dxe_context.protocols[handle][self.loaded_image_protocol_guid]
            loaded_image_protocol = EfiLoadedImageProtocol.EFI_LOADED_IMAGE_PROTOCOL.loadFrom(self.ql, struct_addr)

            unload_ptr = self.ql.unpack64(loaded_image_protocol.Unload)

            if unload_ptr != 0:
                self.ql.log.info(f'Unloading module {handle:#x}, calling {unload_ptr:#x}')

                self.call_function(unload_ptr, [handle], self.end_of_execution_ptr)
                self.loaded_image_protocol_modules.remove(handle)

                return True

        return False

    def execute_module(self, path: str, image_base: int, entry_point: int, eoe_trap: Optional[int]):
        """Start the execution of a UEFI module.

        Args:
            image_base  : module base address
            entry_point : module entry point address
            eoe_trap    : end-of-execution trap address; may be None
        """

        # use familiar UEFI names
        ImageHandle = image_base
        SystemTable = self.gST

        self.call_function(entry_point, [ImageHandle, SystemTable], eoe_trap)
        self.ql.os.entry_point = entry_point

        self.ql.log.info(f'Running from {entry_point:#010x} of {path}')

    def execute_next_module(self):
        if not self.modules or self.ql.os.notify_before_module_execution(self.ql, self.modules[0][0]):
            return

        path, image_base, entry_point = self.modules.pop(0)
        self.execute_module(path, image_base, entry_point, self.end_of_execution_ptr)

    def run(self):
        # intel architecture uefi implementation only
        if self.ql.archtype not in (QL_ARCH.X86, QL_ARCH.X8664):
            raise QlErrorArch("Unsupported architecture")

        # x86-64 arch only
        if self.ql.archtype != QL_ARCH.X8664:
            raise QlErrorArch("Only 64 bit arch is supported at the moment")

        self.loaded_image_protocol_guid = self.ql.os.profile["LOADED_IMAGE_PROTOCOL"]["Guid"]
        self.loaded_image_protocol_modules = []
        self.tpl = 4 # TPL_APPLICATION

        arch_key = {
            QL_ARCH.X86   : "OS32",
            QL_ARCH.X8664 : "OS64"
        }[self.ql.archtype]

        # -------- init BS / RT / DXE data structures and protocols --------

        os_profile = self.ql.os.profile[arch_key]
        self.dxe_context = context.DxeContext(self.ql)

        # initialize and locate heap
        heap_base = int(os_profile["heap_address"], 0)
        heap_size = int(os_profile["heap_size"], 0)
        self.dxe_context.init_heap(heap_base, heap_size)
        self.heap_base_address = heap_base
        self.ql.log.info(f"Located heap at {heap_base:#010x}")

        # initialize and locate stack
        stack_base = int(os_profile["stack_address"], 0)
        stack_size = int(os_profile["stack_size"], 0)
        self.dxe_context.init_stack(stack_base, stack_size)
        sp = stack_base + stack_size - CPU_STACK_ALIGNMENT
        self.ql.log.info(f"Located stack at {sp:#010x}")

        # TODO: statically allocating 256 KiB for ST, RT, BS, DS and Configuration Tables.
        # however, this amount of memory is rather arbitrary
        gST = self.dxe_context.heap.alloc(256 * 1024)
        st.initialize(self.ql, gST)

        protocols = (
            EfiSmmAccess2Protocol,
            EfiSmmBase2Protocol,
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
        self.ql.log.info(f"Located SMM heap at {heap_base:#010x}")

        # TODO: statically allocating 256 KiB for SMM ST.
        # however, this amount of memory is rather arbitrary
        gSmst = self.smm_context.heap.alloc(256 * 1024)
        smst.initialize(self.ql, gSmst)

        self.in_smm = False

        protocols = (
            EfiSmmCpuProtocol,
            EfiSmmSwDispatch2Protocol
        )

        for proto in protocols:
            self.smm_context.install_protocol(proto.descriptor, 1)

        # set stack and frame pointers
        self.ql.reg.rsp = sp
        self.ql.reg.rbp = sp

        self.entry_point = 0
        self.load_address = 0
        self.next_image_base = int(os_profile["image_address"], 0)

        try:
            for dependency in self.ql.argv:
                self.map_and_load(dependency)
        except QlMemoryMappedError:
            self.ql.log.critical("Couldn't map dependency")

        self.ql.log.info(f"Done with loading {self.ql.path}")

        # set up an end-of-execution hook to regain control when module is done
        # executing (i.e. when the entry point function returns). that should be
        # set on a non-executable address, so SystemTable's address was picked
        self.end_of_execution_ptr = gST
        self.ql.hook_address(hook_EndOfExecution, self.end_of_execution_ptr)

        self.execute_next_module()

    def restore_runtime_services(self):
        pass # not sure why do we need to restore RT
