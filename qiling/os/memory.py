#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, re
from typing import Any, Callable, List, MutableSequence, Optional, Sequence, Tuple

from unicorn import UC_PROT_NONE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL

from qiling import Qiling
from qiling.const import *
from qiling.exception import *

# tuple: range start, range end, permissions mask, range label, is mmio?
MapInfoEntry = Tuple[int, int, int, str, bool]

MmioReadCallback  = Callable[[Qiling, int, int], int]
MmioWriteCallback = Callable[[Qiling, int, int, int], None]

class QlMemoryManager:
    """
    some ideas and code from:
    https://github.com/zeropointdynamics/zelos/blob/master/src/zelos/memory.py
    """

    def __init__(self, ql: Qiling):
        self.ql = ql
        self.map_info: MutableSequence[MapInfoEntry] = []
        self.mmio_cbs = {}

        bit_stuff = {
            64 : (1 << 64) - 1,
            32 : (1 << 32) - 1,
            16 : (1 << 20) - 1   # 20bit address line
        }

        if ql.archbit not in bit_stuff:
            raise QlErrorStructConversion("Unsupported Qiling archtecture for memory manager")

        max_addr = bit_stuff[ql.archbit]

        self.max_addr = max_addr
        self.max_mem_addr = max_addr

        # memory page size
        self.pagesize = 0x1000

        # make sure pagesize is a power of 2
        assert self.pagesize & (self.pagesize - 1) == 0, 'pagesize has to be a power of 2'

    def __read_string(self, addr: int) -> str:
        ret = bytearray()
        c = self.read(addr, 1)

        while c[0]:
            ret += c
            addr += 1
            c = self.read(addr, 1)

        return ret.decode()

    def __write_string(self, addr: int, s: str, encoding: str):
        self.write(addr, bytes(s, encoding) + b'\x00')

    # TODO: this is an obsolete utility method that should not be used anymore
    # and here for backward compatibility. use QlOsUtils.read_cstring instead
    def string(self, addr: int, value=None, encoding='utf-8') -> Optional[str]:
        """Read or write string to memory.

        Args:
            addr: source / destination address
            value: string to write, or None if reading one from memory
            encoding: string encoding

        Returns: null-terminated string read from memory, or None if wrote one
        """

        if value is None:
            return self.__read_string(addr)

        self.__write_string(addr, value, encoding)

    def add_mapinfo(self, mem_s: int, mem_e: int, mem_p: int, mem_info: str, is_mmio: bool = False):
        """Add a new memory range to map.

        Args:
            mem_s: memory range start
            mem_e: memory range end
            mem_p: permissions mask
            mem_info: map entry label
            is_mmio: memory range is mmio
        """

        self.map_info.append((mem_s, mem_e, mem_p, mem_info, is_mmio))
        self.map_info = sorted(self.map_info, key=lambda tp: tp[0])

    def del_mapinfo(self, mem_s: int, mem_e: int):
        """Subtract a memory range from map.

        Args:
            mem_s: memory range start
            mem_e: memory range end
        """

        tmp_map_info: MutableSequence[MapInfoEntry] = []

        for s, e, p, info, mmio in self.map_info:
            if e <= mem_s:
                tmp_map_info.append((s, e, p, info, mmio))
                continue

            if s >= mem_e:
                tmp_map_info.append((s, e, p, info, mmio))
                continue

            if s < mem_s:
                tmp_map_info.append((s, mem_s, p, info, mmio))

            if s == mem_s:
                pass

            if e > mem_e:
                tmp_map_info.append((mem_e, e, p, info, mmio))

            if e == mem_e:
                pass

        self.map_info = tmp_map_info

    def change_mapinfo(self, mem_s: int, mem_e: int, mem_p: int = None, mem_info: str = None):
        tmp_map_info: MapInfoEntry = None
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
            self.del_mapinfo(mem_s, mem_e)
            self.add_mapinfo(mem_s, mem_e, mem_p, mem_info if mem_info else tmp_map_info[3])
            return

        if mem_info is not None:
            self.map_info[info_idx] = (tmp_map_info[0], tmp_map_info[1], tmp_map_info[2], mem_info, tmp_map_info[4])

    def get_mapinfo(self) -> Sequence[Tuple[int, int, str, str, Optional[str]]]:
        """Get memory map info.

        Returns: A sequence of 5-tuples representing the memory map entries. Each
        tuple contains range start, range end, permissions, range label and path of
        containing image (or None if not contained by any image)
        """

        def __perms_mapping(ps: int) -> str:
            perms_d = {
                UC_PROT_READ  : 'r',
                UC_PROT_WRITE : 'w',
                UC_PROT_EXEC  : 'x'
            }

            return ''.join(val if idx & ps else '-' for idx, val in perms_d.items())

        def __process(lbound: int, ubound: int, perms: int, label: str, is_mmio: bool) -> Tuple[int, int, str, str, Optional[str]]:
            perms_str = __perms_mapping(perms)

            if hasattr(self.ql, 'os'):
                image = self.ql.os.find_containing_image(lbound)
                container = image.path if image and not is_mmio else None
            else:
                container = None

            return (lbound, ubound, perms_str, label, container)

        return tuple(__process(*entry) for entry in self.map_info)

    def show_mapinfo(self):
        """Emit memory map info in a nicely formatted table.
        """

        # emit title row
        self.ql.log.info(f'{"Start":8s}   {"End":8s}   {"Perm":5s}   {"Label":12s}   {"Image"}')

        # emit table rows
        for lbound, ubound, perms, label, container in self.get_mapinfo():
            self.ql.log.info(f'{lbound:08x} - {ubound:08x}   {perms:5s}   {label:12s}   {container or ""}')

    # TODO: relying on the label string is risky; find a more reliable method
    def get_lib_base(self, filename: str) -> int:
        return next((s for s, _, _, info, _ in self.map_info if os.path.split(info)[1] == filename), -1)

    def align(self, value: int, alignment: int = None) -> int:
        """Align a value down to the specified alignment boundary.

        Args:
            value: a value to align
            alignment: alignment boundary; must be a power of 2. if not specified
            value will be aligned to page size

        Returns: aligned value
        """

        if alignment is None:
            alignment = self.pagesize

        # make sure alignment is a power of 2
        assert alignment & (alignment - 1) == 0

        # round down to nearest alignment
        return value & ~(alignment - 1)

    def align_up(self, value: int, alignment: int = None) -> int:
        """Align a value up to the specified alignment boundary.

        Args:
            value: value to align
            alignment: alignment boundary; must be a power of 2. if not specified
            value will be aligned to page size

        Returns: aligned value
        """

        if alignment is None:
            alignment = self.pagesize

        # make sure alignment is a power of 2
        assert alignment & (alignment - 1) == 0

        # round up to nearest alignment
        return (value + alignment - 1) & ~(alignment - 1)

    def save(self):
        """Save entire memory content.
        """

        mem_dict = {
            "ram" : [],
            "mmio" : []
        }

        for lbound, ubound, perm, label, is_mmio in self.map_info:
            if is_mmio:
                mem_dict['mmio'].append((lbound, ubound, perm, label, *self.mmio_cbs[(lbound, ubound)]))
            else:
                data = self.read(lbound, ubound - lbound)
                mem_dict['ram'].append((lbound, ubound, perm, label, bytes(data)))

        return mem_dict

    def restore(self, mem_dict):
        """Restore saved memory content.
        """

        for lbound, ubound, perms, label, data in mem_dict['ram']:
            self.ql.log.debug(f'restoring memory range: {lbound:#08x} {ubound:#08x} {label}')

            size = ubound - lbound
            if not self.is_mapped(lbound, size):
                self.ql.log.debug(f'mapping {lbound:#08x} {ubound:#08x}, mapsize = {size:#x}')
                self.map(lbound, size, perms, label)

            self.ql.log.debug(f'writing {len(data):#x} bytes at {lbound:#08x}')
            self.write(lbound, data)

        for lbound, ubound, perms, label, read_cb, write_cb in mem_dict['mmio']:
            self.ql.log.debug(f"restoring mmio range: {lbound:#08x} {ubound:#08x} {label}")

            #TODO: Handle overlapped MMIO?
            self.map_mmio(lbound, ubound - lbound, read_cb, write_cb, info=label)

    def read(self, addr: int, size: int) -> bytearray:
        """Read bytes from memory.

        Args:
            addr: source address
            size: amount of bytes to read

        Returns: bytes located at the specified address
        """

        return self.ql.uc.mem_read(addr, size)

    def read_ptr(self, addr: int, size: int=None) -> int:
        """Read an integer value from a memory address.

        Args:
            addr: memory address to read
            size: pointer size (in bytes): either 1, 2, 4, 8, or None for arch native size

        Returns: integer value stored at the specified memory address
        """

        if not size:
            size = self.ql.pointersize

        __unpack = {
            1 : self.ql.unpack8,
            2 : self.ql.unpack16,
            4 : self.ql.unpack32,
            8 : self.ql.unpack64
        }.get(size)

        if __unpack:
            return __unpack(self.read(addr, size))

        raise QlErrorStructConversion(f"Unsupported pointer size: {size}")

    def write(self, addr: int, data: bytes) -> None:
        """Write bytes to a memory.

        Args:
            addr: destination address
            data: bytes to write
        """

        self.ql.uc.mem_write(addr, data)

    def search(self, needle: bytes, begin: int = None, end: int = None) -> Sequence[int]:
        """Search for a sequence of bytes in memory.

        Args:
            needle: bytes sequence to look for
            begin: search starting address (or None to start at lowest avaiable address)
            end: search ending address (or None to end at highest avaiable address)

        Returns: addresses of all matches
        """

        # if starting point not set, search from the first mapped region 
        if begin is None:
            begin = self.map_info[0][0]

        # if ending point not set, search till the last mapped region
        if end is None:
            end = self.map_info[-1][1]

        assert begin < end, 'search arguments do not make sense'

        # narrow the search down to relevant ranges; mmio ranges are excluded due to potential read size effects
        ranges = [(max(begin, lbound), min(ubound, end)) for lbound, ubound, _, _, is_mmio in self.map_info if not (end < lbound or ubound < begin or is_mmio)]
        results = []

        for lbound, ubound in ranges:
            haystack = self.read(lbound, ubound - lbound)
            local_results = (match.start(0) + lbound for match in re.finditer(needle, haystack))

            results.extend(local_results)

        return results

    def unmap(self, addr: int, size: int) -> None:
        """Reclaim a memory range.

        Args:
            addr: range base address
            size: range size (in bytes)
        """

        self.del_mapinfo(addr, addr + size)
        self.ql.uc.mem_unmap(addr, size)

        if (addr, addr + size) in self.mmio_cbs:
            del self.mmio_cbs[(addr, addr+size)]

    def unmap_all(self):
        """Reclaim the entire memory space.
        """

        for begin, end, _ in self.ql.uc.mem_regions():
            if begin and end:
                self.unmap(begin, end - begin + 1)

    def is_available(self, addr: int, size: int) -> bool:
        """Query whether the memory range starting at `addr` and is of length of `size` bytes
        can be allocated.

        Returns: True if it can be allocated, False otherwise
        """

        assert size > 0, 'expected a positive size value'

        begin = addr
        end = addr + size

        # make sure neither begin nor end are enclosed within a mapped range, or entirely enclosing one
        return not any((lbound <= begin < ubound) or (lbound < end <= ubound) or (begin <= lbound < ubound <= end) for lbound, ubound, _, _, _ in self.map_info)

    def is_mapped(self, addr: int, size: int) -> bool:
        """Query whether the memory range starting at `addr` and is of length of `size` bytes
        is mapped, either partially or entirely.

        Returns: True if any part of the specified memory range is taken, False otherwise
        """

        return not self.is_available(addr, size)

    def is_free(self, address, size):
        '''
        The main function of is_free first must fufull is_mapped condition.
        then, check for is the mapped range empty, either fill with 0xFF or 0x00
        Returns true if mapped range is empty else return Flase
        If not not mapped, map it and return true
        '''
        if self.is_mapped(address, size) == True:
            address_end = (address + size)
            while address < address_end:
                mem_read = self.ql.mem.read(address, 0x1)
                if (mem_read[0] != 0x00) and (mem_read[0] != 0xFF):
                    return False
                address += 1
            return True
        else:
            return True


    def find_free_space(self, size: int, minaddr: int = None, maxaddr: int = None, align: int = None) -> int:
        """Locate an unallocated memory that is large enough to contain a range in size of
        `size` and based at `minaddr`.

        Args:
            size: desired range size (in bytes)
            minaddr: lowest base address to consider (or None for minimal address possible)
            maxaddr: highest end address to allow (or None for maximal address possible)
            align: base address alignment, must be a power of 2

        Returns: aligned address of found memory location

        Raises: QlOutOfMemory in case no available memory space found with the specified requirements
        """

        if align is None:
            align = self.pagesize

        # memory space bounds (exclusive)
        mem_lbound = 0
        mem_ubound = self.max_addr + 1

        if minaddr is None:
            minaddr = mem_lbound

        if maxaddr is None:
            maxaddr = mem_ubound

        assert minaddr < maxaddr

        # get gap ranges between mapped ones and memory bounds
        gaps_ubounds = tuple(lbound for lbound, _, _, _, _ in self.map_info) + (mem_ubound,)
        gaps_lbounds = (mem_lbound,) + tuple(ubound for _, ubound, _, _, _ in self.map_info)
        gaps = zip(gaps_lbounds, gaps_ubounds)

        for lbound, ubound in gaps:
            addr = self.align_up(lbound, align)
            end = addr + size

            # is aligned range within gap and satisfying min / max requirements?
            if (lbound <= addr < end <= ubound) and (minaddr <= addr < end <= maxaddr):
                return addr

        raise QlOutOfMemory('Out Of Memory')

    def map_anywhere(self, size: int, minaddr: int = None, maxaddr: int = None, align: int = None, perms: int = UC_PROT_ALL, info: str = None) -> int:
        """Map a region anywhere in memory.

        Args:
            size: desired range size (in bytes)
            minaddr: lowest base address to consider (or None for minimal address possible)
            maxaddr: highest end address to allow (or None for maximal address possible)
            align: base address alignment, must be a power of 2
            perms: requested permissions mask
            info: range label string

        Returns: mapped address
        """

        if align is None:
            align = self.pagesize

        size = self.align_up(size)
        addr = self.find_free_space(size, minaddr, maxaddr, align)

        self.map(addr, size, perms, info)

        return addr

    def protect(self, addr: int, size: int, perms):
        # mask off perms bits that are not supported by unicorn
        perms &= UC_PROT_ALL

        aligned_address = self.align(addr)
        aligned_size = self.align_up((addr & (self.pagesize - 1)) + size)

        self.ql.uc.mem_protect(aligned_address, aligned_size, perms)
        self.change_mapinfo(aligned_address, aligned_address + aligned_size, mem_p = perms)


    def map(self, addr: int, size: int, perms: int = UC_PROT_ALL, info: str = None):
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
            raise QlMemoryMappedError('Requested memory is unavailable')

        self.ql.uc.mem_map(addr, size, perms)
        self.add_mapinfo(addr, addr + size, perms, info or '[mapped]', is_mmio=False)

    def map_mmio(self, addr: int, size: int, read_cb: Optional[MmioReadCallback], write_cb: Optional[MmioWriteCallback], info: str = '[mmio]'):
        # TODO: mmio memory overlap with ram? Is that possible?
        # TODO: Can read_cb or write_cb be None? How uc handle that access?
        prot = UC_PROT_NONE

        if read_cb:
            prot |= UC_PROT_READ

        if write_cb:
            prot |= UC_PROT_WRITE

        # generic mmio read wrapper
        def __mmio_read(uc, offset: int, size: int, user_data: MmioReadCallback):
            cb = user_data

            return cb(self.ql, offset, size)

        # generic mmio write wrapper
        def __mmio_write(uc, offset: int, size: int, value: int, user_data: MmioWriteCallback):
            cb = user_data

            cb(self.ql, offset, size, value)

        self.ql.uc.mmio_map(addr, size, __mmio_read, read_cb, __mmio_write, write_cb)
        self.add_mapinfo(addr, addr + size, prot, info, is_mmio=True)

        self.mmio_cbs[(addr, addr + size)] = (read_cb, write_cb)

# A Simple Heap Implementation
class Chunk:
    def __init__(self, address: int, size: int):
        self.inuse = True
        self.address = address
        self.size = size

class QlMemoryHeap:
    def __init__(self, ql: Qiling, start_address: int, end_address: int):
        self.ql = ql
        self.chunks: List[Chunk] = []

        # heap boundaries
        self.start_address = start_address
        self.end_address = end_address

        # size of consecutive memory currently allocated for heap use
        # invariant: current_alloc is aligned to memory page size
        self.current_alloc = 0

        # size of consecutive memory currently used for chunks
        # invariant: current_use never exceeds current_alloc
        self.current_use = 0

        # keep track of all memory regions allocated for heap use
        self.mem_alloc = []

    def save(self) -> Mapping[str, Any]:
        saved_state = {
            'chunks'        : self.chunks,
            'start_address' : self.start_address,
            'end_address'   : self.end_address,
            'current_alloc' : self.current_alloc,
            'current_use'   : self.current_use,
            'mem_alloc'     : self.mem_alloc
        }

        return saved_state

    def restore(self, saved_state: Mapping[str, Any]):
        self.chunks         = saved_state['chunks']
        self.start_address  = saved_state['start_address']
        self.end_address    = saved_state['end_address']
        self.current_alloc  = saved_state['current_alloc']
        self.current_use    = saved_state['current_use']
        self.mem_alloc      = saved_state['mem_alloc']

    def alloc(self, size: int) -> int:
        """Allocate heap memory.

        Args:
            size: requested allocation size in bytes

        Returns:
            The address of the newly allocated memory chunk, or 0 if allocation has failed
        """

        # attempt to recycle an existing unused chunk first.
        # locate the smallest available chunk that has enough room
        chunk = min((chunk for chunk in self.chunks if (not chunk.inuse) and (chunk.size >= size)), default=None, key=lambda ch: ch.size)

        # if could not find any, create a new one
        if chunk is None:
            # is new chunk going to exceed currently allocated heap space?
            # in case it does, allocate additional heap space
            if self.current_use + size > self.current_alloc:
                real_size = self.ql.mem.align_up(size)

                # if that additional allocation is going to exceed heap upper bound, fail
                if self.start_address + self.current_use + real_size > self.end_address:
                    return 0

                self.ql.mem.map(self.start_address + self.current_alloc, real_size, info="[heap]")
                self.mem_alloc.append((self.start_address + self.current_alloc, real_size))
                self.current_alloc += real_size

            chunk = Chunk(self.start_address + self.current_use, size)
            self.current_use += size
            self.chunks.append(chunk)

        chunk.inuse = True
        return chunk.address

    def size(self, addr: int) -> int:
        """Get the size of allocated memory chunk starting at a specific address.

        Args:
            addr: chunk starting address

        Returns: chunk size (in bytes), or 0 if no chunk starts at that address
        """

        # find used chunk starting at specified address
        chunk = self._find(addr, inuse=True)

        return chunk.size if chunk else 0

    def free(self, addr: int) -> bool:
        """Free up memory at a specific address.

        Args:
            addr: address of memory to free

        Returns: True iff memory was freed successfully, False otherwise
        """

        # find used chunk starting at specified address
        chunk = self._find(addr, inuse=True)

        if not chunk:
            return False

        # clear in-use indication
        chunk.inuse = False
        return True

    # clear all memory regions alloc
    def clear(self):
        for chunk in self.chunks:
            chunk.inuse = False

        for addr, size in self.mem_alloc:
            self.ql.mem.unmap(addr, size)

        self.mem_alloc.clear()

        self.current_alloc = 0
        self.current_use = 0

    def _find(self, addr: int, inuse: bool = None) -> Optional[Chunk]:
        """Find a chunk starting at a specified address.

        Args:
            addr: starting address of the requested chunk
            inuse: whether the chunk should be in-use; None if dont care

        Returns: chunk instance starting at specified address whose in-use status is set
        as required (if required), None if no such chunk was found
        """

        # nullify the in-use check in case the caller doesn't care about it
        dontcare = True if inuse is None else False

        return next((chunk for chunk in self.chunks if addr == chunk.address and (dontcare or chunk.inuse == inuse)), None)
