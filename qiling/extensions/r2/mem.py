import ctypes


from qiling.os.memory import QlMemoryManager, MapInfoEntry
from qiling.exception import QlMemoryMappedError

from typing import Any, Callable, Iterator, List, Mapping, MutableSequence, Optional, Pattern, Sequence, Tuple, Union

from unicorn import UC_PROT_NONE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL

class R2Mem(QlMemoryManager):
    '''A wrapper for QlMemoryManager that uses map_ptr and store raw memory in map_info
       NOTE: ql.mem already contains map_infor after loader.run(), so instead of super().__init__(),
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
            for line in self.get_formatted_mapinfo():
                print(line)
            raise QlMemoryMappedError(f'Requested memory {addr:#x} + {size:#x} is unavailable')

        buf = self.map_ptr(addr, size, perms, ptr)
        self.add_mapinfo(addr, addr + size, perms, info or '[mapped]', is_mmio=False, data=buf)
    
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
        self.cmap[addr] = cdata
        self.ql.uc.mem_map_ptr(addr, size, perms, cdata)
        return buf

    def add_mapinfo(self, mem_s: int, mem_e: int, mem_p: int, mem_info: str, is_mmio: bool = False, data : bytearray = None):
        """Add a new memory range to map.

        Args:
            mem_s: memory range start
            mem_e: memory range end
            mem_p: permissions mask
            mem_info: map entry label
            is_mmio: memory range is mmio
        """
        self.map_info.append((mem_s, mem_e, mem_p, mem_info, is_mmio, data))
        self.map_info.sort(key=lambda tp: tp[0])

    def del_mapinfo(self, mem_s: int, mem_e: int):
        """Subtract a memory range from map, will destroy data and unmap uc mem in the range.

        Args:
            mem_s: memory range start
            mem_e: memory range end
        """

        tmp_map_info: MutableSequence[MapInfoEntry] = []

        for s, e, p, info, mmio, data in self.map_info:
            if e <= mem_s:
                tmp_map_info.append((s, e, p, info, mmio, data))
                continue

            if s >= mem_e:
                tmp_map_info.append((s, e, p, info, mmio, data))
                continue

            del self.cmap[s]  # remove cdata reference starting at s
            if s < mem_s:
                self.ql.uc.mem_unmap(s, mem_s - s)
                self.map_ptr(s, mem_s - s, p, data[:mem_s - s])
                tmp_map_info.append((s, mem_s, p, info, mmio, data[:mem_s - s]))

            if s == mem_s:
                pass

            if e > mem_e:
                self.ql.uc.mem_unmap(mem_e, e - mem_e)
                self.map_ptr(mem_e, e - mem_e, p, data[mem_e - e:])
                tmp_map_info.append((mem_e, e, p, info, mmio, data[mem_e - e:]))

            if e == mem_e:
                pass

            del data[mem_s - s:mem_e - s]

        self.map_info = tmp_map_info

    def change_mapinfo(self, mem_s: int, mem_e: int, mem_p: Optional[int] = None, mem_info: Optional[str] = None, data: Optional[bytearray] = None):
        tmp_map_info: Optional[MapInfoEntry] = None
        info_idx: int = None

        for idx, map_info in enumerate(self.map_info):
            if mem_s >= map_info[0] and mem_e <= map_info[1]:
                tmp_map_info = map_info
                info_idx = idx
                break

        if tmp_map_info is None:
            self.ql.log.error(f'Cannot change mapinfo at {mem_s:#08x}-{mem_e:#08x}')
            return

        if mem_p is not None:
            data = data or self.read(mem_s, mem_e - mem_s).copy()
            assert(len(data) == mem_e - mem_s)
            self.unmap(mem_s, mem_e - mem_s)
            self.map_ptr(mem_s, mem_e - mem_s, mem_p, data)
            self.add_mapinfo(mem_s, mem_e, mem_p, mem_info or tmp_map_info[3], tmp_map_info[4], data)
            return

        if mem_info is not None:
            self.map_info[info_idx] = (tmp_map_info[0], tmp_map_info[1], tmp_map_info[2], mem_info, tmp_map_info[4], tmp_map_info[5])
    
    def save(self):
        """Save entire memory content.
        """

        mem_dict = {
            "ram" : [],
            "mmio" : []
        }

        for lbound, ubound, perm, label, is_mmio, data in self.map_info:
            if is_mmio:
                mem_dict['mmio'].append((lbound, ubound, perm, label, *self.mmio_cbs[(lbound, ubound)]))
            else:
                data = self.read(lbound, ubound - lbound)  # read instead of using data from map_info to avoid error
                mem_dict['ram'].append((lbound, ubound, perm, label, data))

        return mem_dict

    def restore(self, mem_dict):
        """Restore saved memory content.
        """

        for lbound, ubound, perms, label, data in mem_dict['ram']:
            self.ql.log.debug(f'restoring memory range: {lbound:#08x} {ubound:#08x} {label}')

            size = ubound - lbound
            if self.is_available(lbound, size):
                self.ql.log.debug(f'mapping {lbound:#08x} {ubound:#08x}, mapsize = {size:#x}')
                self.map(lbound, size, perms, label, data)

            self.ql.log.debug(f'writing {len(data):#x} bytes at {lbound:#08x}')
            self.write(lbound, bytes(data))

        for lbound, ubound, perms, label, read_cb, write_cb in mem_dict['mmio']:
            self.ql.log.debug(f"restoring mmio range: {lbound:#08x} {ubound:#08x} {label}")

            #TODO: Handle overlapped MMIO?
            self.map_mmio(lbound, ubound - lbound, read_cb, write_cb, info=label)
