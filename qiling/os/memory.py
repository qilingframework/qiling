#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from qiling.const import *
from qiling.exception import *
from qiling.os.utils import *

from unicorn import (
    UC_PROT_ALL,
    UC_PROT_EXEC,
    UC_PROT_NONE,
    UC_PROT_READ,
    UC_PROT_WRITE,
)

class QlMemoryManager:
    """
    some ideas and code from:
    https://github.com/zeropointdynamics/zelos/blob/master/src/zelos/memory.py
    """

    def __init__(self, ql, max_addr):
        self.ql = ql
        self.max_mem_addr = max_addr
        self.max_addr = max_addr
        self.map_info = []


    def add_mapinfo(self, mem_s, mem_e, mem_p, mem_info):
        tmp_map_info = []
        insert_flag = 0
        map_info = self.map_info
        if len(map_info) == 0:
            tmp_map_info.append([mem_s, mem_e, mem_p, mem_info])
        else:
            for s, e, p, info in map_info:
                if e <= mem_s:
                    tmp_map_info.append([s, e, p, info])
                    continue
                if s >= mem_e:
                    if insert_flag == 0:
                        insert_flag = 1
                        tmp_map_info.append([mem_s, mem_e, mem_p, mem_info])
                    tmp_map_info.append([s, e, p, info])
                    continue
                if s < mem_s:
                    tmp_map_info.append([s, mem_s, p, info])

                if s == mem_s:
                    pass

                if insert_flag == 0:
                    insert_flag = 1
                    tmp_map_info.append([mem_s, mem_e, mem_p, mem_info])

                if e > mem_e:
                    tmp_map_info.append([mem_e, e, p, info])

                if e == mem_e:
                    pass
            if insert_flag == 0:
                tmp_map_info.append([mem_s, mem_e, mem_p, mem_info])
        map_info = []
        map_info.append(tmp_map_info[0])

        for s, e, p, info in tmp_map_info[1:]:
            if s == map_info[-1][1] and info == map_info[-1][3] and p == map_info[-1][2]:
                map_info[-1][1] = e
            else:
                map_info.append([s, e, p, info])

        self.map_info = map_info


    def del_mapinfo(self, mem_s, mem_e):
        tmp_map_info = []

        for s, e, p, info in self.map_info:
            if e <= mem_s:
                tmp_map_info.append([s, e, p, info])
                continue

            if s >= mem_e:
                tmp_map_info.append([s, e, p, info])
                continue

            if s < mem_s:
                tmp_map_info.append([s, mem_s, p, info])

            if s == mem_s:
                pass

            if e > mem_e:
                tmp_map_info.append([mem_e, e, p, info])

            if e == mem_e:
                pass

        self.map_info = tmp_map_info


    def show_mapinfo(self):
        self.ql.nprint("[+] Start      End        Perm.  Path\n")
        for s, e, p, info in self.map_info:
            self.ql.nprint("[+] %08x - %08x - %s    %s\n" % (s, e, p, info))


    def get_lib_base(self, filename):
        for s, e, p, info in self.map_info:
            if os.path.split(info)[1] == filename:
                return s
        return -1


    def _align(self, addr, alignment=0x1000):
        # rounds up to nearest alignment
        mask = ((1 << self.ql.archbit) - 1) & -alignment
        return (addr + (alignment - 1)) & mask


    def read(self, addr: int, size: int) -> bytearray:
        return self.ql.uc.mem_read(addr, size)


    def write(self, addr: int, data: bytes) -> None:
        return self.ql.uc.mem_write(addr, data)


    def unmap(self, addr, size) -> None:
        '''
        The main function of mem_unmap is to reclaim memory.
        This function will reclaim the memory starting with addr and length of size.
        Upon successful completion, munmap() shall return 0; 
        otherwise, it shall return -1 and set errno to indicate the error.
        '''
        self.del_mapinfo(addr, addr + size)
        self.ql.uc.mem_unmap(addr, size)


    def unmap_all(self):
        for region in list(self.ql.uc.mem_regions()):
            if region[0] and region[1]:
                return self.unmap(region[0], ((region[1] - region[0])+0x1))


    def is_available(self, addr, size):
        '''
        The main function of is_available is to determine 
        whether the memory starting with addr and having a size of length can be used for allocation.

        If it can be allocated, returns True.

        If it cannot be allocated, it returns False.
        '''
        try:
            self.map(addr, addr)
        except:
            return False    
        
        self.unmap(addr, addr)
        return True


    def is_mapped(self, address, size): 
        '''
        The main function of is_mmaped is to determine 
        whether the memory starting with addr and size has been mapped.
        Returns true if it has already been allocated.
        If unassigned, returns False.
        '''   
        for region in list(self.ql.uc.mem_regions()):
            if address >= region[0] and (address + size -1) <= region[1]:
                return True

        return False
        
    
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


    def find_free_space(
        self, size, min_addr=0, max_addr = 0, alignment=0x10000
    ):
        """
        Finds a region of memory that is free, larger than 'size' arg,
        and aligned.
        """
        mapped = []
        
        for address_start, address_end, perm, info in self.ql.mem.map_info:
            mapped += [[address_start, (address_end - address_start)]]
        
        for address_start, address_end, perms in self.ql.uc.mem_regions():
            mapped += [[address_start, (address_end - address_start)]]
        
        for i in range(0, len(mapped)):
            addr = self._align(
                mapped[i][0] + mapped[i][1], alignment=alignment
            )
            # Enable allocating memory in the middle of a gap when the
            # min requested address falls in the middle of a gap
            if addr < min_addr:
                addr = min_addr
            # Cap the gap's max address by accounting for the next
            # section's start address, requested max address, and the
            # max possible address

            max_gap_addr = (
                self.max_addr
                if i == len(mapped) - 1
                else mapped[i + 1][1]
            )

            max_gap_addr = min(max_gap_addr, self.max_mem_addr)
            # Ensure the end address is less than the max and the start
            # address is free
            if addr + size < max_gap_addr and self.is_mapped(addr, size) == False:
                return addr
        raise QlOutOfMemory("[!] Out Of Memory")


    def map_anywhere(
        self,
        size,
        #name = "",
        #kind = "",
        min_addr = 0,
        alignment = 0x1000,
        #prot: int = ProtType.RWX,
    ) -> int:
        """
        Maps a region of memory with requested size, within the
        addresses specified. The size and start address will respect the
        alignment.

        Args:
            size: # of bytes to map. This will be rounded up to match
                the alignment.
            name: String used to identify mapped region. Used for
                debugging.
            kind: String used to identify the purpose of the mapped
                region. Used for debugging.
            min_addr: The lowest address that could be mapped.
            max_addr: The highest address that could be mapped.
            alignment: Ensures the size and start address are multiples
                of this. Must be a multiple of 0x1000. Default 0x1000.
            prot: RWX permissions of the mapped region. Defaults to
                granting all permissions.
        Returns:
            Start address of mapped region.
        """
        max_mem_addr = self.max_mem_addr
        address = self.find_free_space(
            size, min_addr=min_addr, max_addr=max_mem_addr, alignment=alignment
        )
        """
        we need a better mem_map as defined in the issue
        """
        #self.map(address, util.align(size), name, kind)
        self.map(address, self._align(size))
        return address

    def protect(self, addr, size, perms):
        aligned_address = addr & 0xFFFFF000  # Address needs to align with
        aligned_size = self._align((addr & 0xFFF) + size)
        self.ql.uc.mem_protect(aligned_address, aligned_size, perms)


    def map(self, addr, size, perms=UC_PROT_ALL, ptr = None):
        '''
	    The main function of mem_mmap is to implement memory allocation in unicorn, 
	    which is slightly similar to the function of syscall_mmap. 

	    When the memory can satisfy the given addr and size, 
	    it needs to be allocated to the corresponding address space.
	    
	    Upon successful completion, mem_map() shall return 0; 

    	otherwise, it shall return -1 and set errno to indicate the error.
         
        is should call other API to get_available mainly gives a length, 
        and then the memory manager returns  an address that can apply for that length.

        '''
        if ptr == None:
            if self.is_mapped(addr, size) == False:
               self.add_mapinfo(addr, addr + size, 'rw-', "[mapped]")
               self.ql.uc.mem_map(addr, size)
            else:
                raise QlMemoryMappedError("[!] Memory Mapped")    
            
            if perms != UC_PROT_ALL:
                self.protect(addr, size, perms)
        else:
            self.ql.uc.mem_map_ptr(addr, size, perms, ptr)

# A Simple Heap Implementation
class Chunk():
    def __init__(self, address, size):
        self.inuse = True
        self.address = address
        self.size = size

    @staticmethod
    def compare(chunk):
        return chunk.size

class Heap:
    def __init__(self, ql, start_address, end_address):
        self.ql = ql
        self.chunks = []
        self.start_address = start_address
        self.end_address = end_address
        # unicorn needs 0x1000
        self.page_size = 0x1000
        # current alloced memory size
        self.current_alloc = 0
        # curent use memory size
        self.current_use = 0

    def _align(self, size, unit):
        return (size // unit + (1 if size % unit else 0)) * unit     

    def mem_alloc(self, size):
        
        if self.ql.archtype== QL_X86:
            size = self._align(size, 4)
        elif self.ql.archtype== QL_X8664:
            size = self._align(size, 8)
        else:
            raise QlErrorArch("[!] Unknown ql.arch")

        # Find the heap chunks that best matches size 
        self.chunks.sort(key=Chunk.compare)
        for chunk in self.chunks:
            if chunk.inuse is False and chunk.size > size:
                chunk.inuse = True
                return chunk.address

        chunk = None
        # If we need mem_map new memory
        if self.current_use + size > self.current_alloc:
            real_size = self._align(size, self.page_size)
            # If the heap is not enough
            if self.start_address + self.current_use + real_size > self.end_address:
                return 0
            self.ql.mem.map(self.start_address + self.current_alloc, real_size)
            chunk = Chunk(self.start_address + self.current_use, size)
            self.current_alloc += real_size
            self.current_use += size
            self.chunks.append(chunk)
        else:
            chunk = Chunk(self.start_address + self.current_use, size)
            self.current_use += size
            self.chunks.append(chunk)

        chunk.inuse = True
        # print("heap.mem_alloc addresss: " + hex(chunk.address))
        return chunk.address

    def mem_size(self, addr):
        for chunk in self.chunks:
            if addr == chunk.address and chunk.inuse:
                return chunk.size
        return 0

    def mem_free(self, addr):
        for chunk in self.chunks:
            if addr == chunk.address and chunk.inuse:
                chunk.inuse = False
                return True
        return False
