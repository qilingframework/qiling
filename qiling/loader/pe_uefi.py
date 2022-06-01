#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from pefile import PE
from typing import Any, Mapping, Optional, Sequence

from qiling import Qiling
from qiling.const import QL_ARCH
from qiling.exception import QlErrorArch, QlMemoryMappedError
from qiling.loader.loader import QlLoader, Image
from qiling.os.const import PARAM_INTN, POINTER

from qiling.os.uefi import st, smst, utils
from qiling.os.uefi.context import DxeContext, SmmContext, UefiContext
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

        self.dxe_context: DxeContext
        self.smm_context: SmmContext
        self.context: UefiContext

    # list of members names to save and restore
    __save_members = (
        'modules',
        'events',
        'notify_list',
        'tpl'
    )

    def save(self) -> Mapping[str, Any]:
        saved_state = super(QlLoaderPE_UEFI, self).save()

        for member in QlLoaderPE_UEFI.__save_members:
            saved_state[member] = getattr(self, member)

        # since this class initialize the heap (that is hosted by the OS object), we will store it here
        saved_state['heap'] = self.ql.os.heap.save()

        return saved_state

    def restore(self, saved_state: Mapping[str, Any]):
        super(QlLoaderPE_UEFI, self).restore(saved_state)

        for member in QlLoaderPE_UEFI.__save_members:
            setattr(self, member, saved_state[member])

        self.ql.os.heap.restore(saved_state['heap'])

    def install_loaded_image_protocol(self, image_base: int, image_size: int):
        fields = {
            'gST'        : self.gST,
            'image_base' : image_base,
            'image_size' : image_size
        }

        descriptor = EfiLoadedImageProtocol.make_descriptor(fields)
        self.context.install_protocol(descriptor, image_base)

        self.context.loaded_image_protocol_modules.append(image_base)

    def map_and_load(self, path: str, context: UefiContext, exec_now: bool=False):
        """Map and load a module into memory.

        The specified module would be mapped and loaded into the address set
        in the `next_image_base` member. It is the caller's responsibility to
        make sure that the memory is available.

        On success, `next_image_base` will be updated accordingly.

        Args:
            path     : path of the module binary to load
            context  : uefi context the module belongs to
            exec_now : execute module right away; will be enququed if not

        Raises:
            QlMemoryMappedError : when `next_image_base` is not available
        """

        ql = self.ql
        pe = PE(path, fast_load=True)

        # use image base only if it does not point to NULL
        image_base = pe.OPTIONAL_HEADER.ImageBase or context.next_image_base
        image_size = ql.mem.align_up(pe.OPTIONAL_HEADER.SizeOfImage)

        assert (image_base % ql.mem.pagesize) == 0, 'image base is expected to be page-aligned'

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

        # this would be used later be loader.find_containing_image
        self.images.append(Image(image_base, image_base + image_size, path))

        # update next memory slot to allow sequencial loading. its availability
        # is unknown though
        context.next_image_base = image_base + image_size

        module_info = (path, image_base, entry_point, context)

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

        types = (PARAM_INTN, ) * len(args)
        targs = tuple(zip(types, args))

        self.ql.os.fcall.call_native(addr, targs, ret)

    def unload_modules(self, context: UefiContext) -> bool:
        """Invoke images unload callbacks, if set.

        Args:
            context: uefi context instance

        Returns: `True` to stop the teardown process, `False` to proceed
        """

        for handle in context.loaded_image_protocol_modules:
            struct_addr = context.protocols[handle][self.loaded_image_protocol_guid]
            loaded_image_protocol = EfiLoadedImageProtocol.EFI_LOADED_IMAGE_PROTOCOL.loadFrom(self.ql, struct_addr)

            unload_ptr = loaded_image_protocol.Unload.value

            if unload_ptr != 0:
                self.ql.log.info(f'Unloading module {handle:#x}, calling {unload_ptr:#x}')

                self.ql.os.fcall.call_native(unload_ptr, ((POINTER, handle),), context.end_of_execution_ptr)
                context.loaded_image_protocol_modules.remove(handle)

                return True

        return False

    def execute_module(self, path: str, image_base: int, entry_point: int, context: UefiContext, eoe_trap: Optional[int]):
        """Start the execution of a UEFI module.

        Args:
            image_base  : module base address
            entry_point : module entry point address
            context     : module execution context (either dxe or smm)
            eoe_trap    : end-of-execution trap address; may be None
        """

        # use familiar UEFI names
        ImageHandle = image_base
        SystemTable = self.gST

        # set effectively active heap
        self.ql.os.heap = context.heap

        # set stack and frame pointers
        self.ql.arch.regs.rsp = context.top_of_stack
        self.ql.arch.regs.rbp = context.top_of_stack

        self.ql.os.fcall.call_native(entry_point, (
            (POINTER, ImageHandle),
            (POINTER, SystemTable)
        ), eoe_trap)

        self.ql.os.running_module = path
        self.ql.os.entry_point = entry_point
        self.ql.log.info(f'Running from {entry_point:#010x} of {path}')

    def execute_next_module(self):
        if not self.modules:
            return

        path, image_base, entry_point, context = self.modules.pop(0)

        if self.ql.os.notify_before_module_execution(path):
            return

        self.execute_module(path, image_base, entry_point, context, context.end_of_execution_ptr)

    def __init_dxe_environment(self, ql: Qiling) -> DxeContext:
        """Initialize DXE data structures (BS, RT and DS) and install essential protocols.
        """

        profile = ql.os.profile['DXE']
        context = DxeContext(ql)

        # initialize and locate heap
        heap_base = int(profile['heap_address'], 0)
        heap_size = int(profile['heap_size'], 0)
        context.init_heap(heap_base, heap_size)
        ql.log.info(f'DXE heap at {heap_base:#010x}')

        # initialize and locate stack
        stack_base = int(profile['stack_address'], 0)
        stack_size = int(profile['stack_size'], 0)
        context.init_stack(stack_base, stack_size)
        ql.log.info(f'DXE stack at {context.top_of_stack:#010x}')

        # base address for next image
        context.next_image_base = int(profile['image_address'], 0)

        # statically allocating 4 KiB for ST, RT, BS, DS and about 100 configuration table entries.
        # the actual size needed was rounded up to the nearest page boundary.
        gST = context.heap.alloc(4 * 1024)

        # TODO: statically allocating 64 KiB for data pointed by configuration table.
        # note that this amount of memory was picked arbitrarily
        conf_data = context.heap.alloc(64 * 1024)

        context.conf_table_data_ptr = conf_data
        context.conf_table_data_next_ptr = conf_data

        # the end of execution hook should be set on an address that is not expected to be
        # executed, like the system table location
        context.end_of_execution_ptr = gST

        st.initialize(ql, context, gST)

        protocols = (
            EfiSmmAccess2Protocol,
            EfiSmmBase2Protocol,
        )

        for p in protocols:
            context.install_protocol(p.descriptor, 1)

        return context

    def __init_smm_environment(self, ql: Qiling) -> SmmContext:
        """Initialize SMM data structures (SMST and SmmRT) and install essential protocols.
        """

        profile = ql.os.profile['SMM']
        context = SmmContext(ql)

        # set smram boundaries
        context.smram_base = int(profile["smram_base"], 0)
        context.smram_size = int(profile["smram_size"], 0)

        # initialize and locate heap
        heap_base = int(profile["heap_address"], 0)
        heap_size = int(profile["heap_size"], 0)
        context.init_heap(heap_base, heap_size)
        ql.log.info(f"SMM heap at {heap_base:#010x}")

        # initialize and locate stack
        stack_base = int(profile['stack_address'], 0)
        stack_size = int(profile['stack_size'], 0)
        context.init_stack(stack_base, stack_size)
        ql.log.info(f'SMM stack at {context.top_of_stack:#010x}')

        # base address for next image
        context.next_image_base = int(profile['image_address'], 0)

        # statically allocating 4 KiB for SMM ST and about 100 configuration table entries
        # the actual size needed was rounded up to the nearest page boundary.
        gSmst = context.heap.alloc(4 * 1024)

        # TODO: statically allocating 64 KiB for data pointed by configuration table.
        # note that this amount of memory was picked arbitrarily
        conf_data = context.heap.alloc(64 * 1024)

        context.conf_table_data_ptr = conf_data
        context.conf_table_data_next_ptr = conf_data

        # the end of execution hook should be set on an address that is not expected to be
        # executed, like the system table location
        context.end_of_execution_ptr = gSmst

        smst.initialize(ql, context, gSmst)

        protocols = (
            EfiSmmCpuProtocol,
            EfiSmmSwDispatch2Protocol
        )

        for p in protocols:
            context.install_protocol(p.descriptor, 1)

        return context

    def run(self):
        ql = self.ql

        # intel architecture uefi implementation only
        if ql.arch.type not in (QL_ARCH.X86, QL_ARCH.X8664):
            raise QlErrorArch("Unsupported architecture")

        # x86-64 arch only
        if ql.arch.type != QL_ARCH.X8664:
            raise QlErrorArch("Only 64-bit modules are supported at the moment")

        self.loaded_image_protocol_guid = ql.os.profile["LOADED_IMAGE_PROTOCOL"]["Guid"]
        self.tpl = 4 # TPL_APPLICATION

        # TODO: assign context to os rather than loader
        self.dxe_context = self.__init_dxe_environment(ql)
        self.smm_context = self.__init_smm_environment(ql)

        self.entry_point = 0
        self.load_address = 0

        try:
            for dependency in ql.argv:

                # TODO: determine whether this is an smm or dxe module
                is_smm_module = 'Smm' in dependency

                if is_smm_module:
                    self.context = self.smm_context
                else:
                    self.context = self.dxe_context

                self.map_and_load(dependency, self.context)

            ql.log.info(f"Done loading modules")

        except QlMemoryMappedError:
            ql.log.critical("Could not map dependency")

        self.set_exit_hook(self.dxe_context.end_of_execution_ptr)
        self.set_exit_hook(self.smm_context.end_of_execution_ptr)

        self.execute_next_module()

    def set_exit_hook(self, address: int):
        """Set up an end-of-execution hook to regain control when module is done
        executing; i.e. when the module entry point function returns.
        """

        def __module_exit_trap(ql: Qiling):
            # this trap will be called when the current module entry point function
            # returns. this is done do regain control, run necessary tear down code
            # and proceed to the execution of the next module. if no more modules
            # left, terminate gracefully.
            #
            # the tear down code may include queued protocol notifications and module
            # unload callbacks. in such case the trap returns without calling 'os.stop'
            # and the execution resumes with the current cpu state.
            #
            # note that the trap may be called multiple times for a single module,
            # every time a tear down code needs to be executed, or for any other
            # reason defined by the user.

            if ql.os.notify_after_module_execution(len(self.modules)):
                return

            if utils.execute_protocol_notifications(ql):
                return

            if self.modules:
                self.execute_next_module()
            else:
                if self.unload_modules(self.smm_context) or self.unload_modules(self.dxe_context):
                    return

                ql.log.info(f'No more modules to run')
                ql.os.stop()

        self.ql.hook_address(__module_exit_trap, address)
