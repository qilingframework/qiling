import ctypes


from qiling.os.memory import QlMemoryManager, MapInfoEntry
from qiling.exception import QlMemoryMappedError

from typing import Any, Callable, Iterator, List, Mapping, MutableSequence, Optional, Pattern, Sequence, Tuple, Union

from unicorn import UC_PROT_NONE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL

class R2Mem(QlMemoryManager):
    '''A wrapper for QlMemoryManager that uses map_ptr and store raw memory in map_info
       NOTE: ql.mem already contains map_info after loader.run(), so instead of super().__init__(),
       we accept mem object to simulate inheritance by composition 
    '''

    def __init__(self, mem: QlMemoryManager):
        self.__dict__.update(mem.__dict__)
        self._convert_map()

    def _convert_map(self):
        '''Clean existing map_info and remap memory'''
        mapinfo = self.map_info.copy()
        self.map_info = []
        self.cmap = {}
        for s, e, p, label, _mmio in mapinfo:
          data = self.read(s, e - s)
          self.ql.uc.mem_unmap(s, e - s)
          self.map(s, e - s, p, label, data)
    
    def map(self, addr: int, size: int, perms: int = UC_PROT_ALL, info: Optional[str] = None, ptr: Optional[bytearray] = None):
        """Map a new memory range.

        Args:
            addr: memory range base address
            size: memory range size (in bytes)
            perms: requested permissions mask
            info: range label string
            ptr: pointer to use (if any)

        Raises:
            QlMemoryMappedError: in case requested memory range is not fully available
        """

        assert perms & ~UC_PROT_ALL == 0, f'unexpected permissions mask {perms}'
        
        if not self.is_available(addr, size):
            raise QlMemoryMappedError(f'Requested memory {addr:#x} + {size:#x} is unavailable')

        self.map_ptr(addr, size, perms, ptr)
        self.add_mapinfo(addr, addr + size, perms, info or '[mapped]', is_mmio=False)
    
    def map_ptr(self, addr: int, size: int, perms: int = UC_PROT_ALL, buf: Optional[bytearray] = None) -> bytearray:
        """Map a new memory range allocated as Python bytearray, will not affect map_info

        Args:
            addr: memory range base address
            size: memory range size (in bytes)
            perms: requested permissions mask
            buf: bytearray already allocated (if any)

        Returns:
            bytearray with size, should be added to map_info by caller
        """
        buf = buf or bytearray(size)
        buf_type = ctypes.c_ubyte * size
        cdata = buf_type.from_buffer(buf)
        self.cmap[addr] = cdata  # NOTE: will memory leak or invalid reference happen if not updated when splitting memory?
        self.ql.uc.mem_map_ptr(addr, size, perms, cdata)
        return buf
