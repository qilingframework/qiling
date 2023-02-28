from typing import List
from qiling import Qiling
from qiling.core_hooks_types import HookRet
import re
from capstone import CsInsn, Cs

class History:
    history_hook_handle: HookRet = None
    history: List[CsInsn] = []
    ql: Qiling
    md: Cs

    def __init__(self, ql: Qiling) -> None:
        self.ql = ql
        self.track_block_coverage()
        self.md = ql.arch.disassembler

    def clear_history(self) -> None:
        """Clears the current state of the history 
        
        """
        self.history = []

    def clear_hooks(self) -> None:
        """Clears the current history hook from the Qiling instance

        Returns:
            None 
        """

        self.ql.hook_del(self.history_hook_handle)

    def track_block_coverage(self) -> None:
        """Configures the history plugin to track all of the basic blocks that are executed. Removes any existing hooks
        
        Returns:
            None
        """
        if self.history_hook_handle:
            self.clear_hooks()
        
        def __hook_block(ql, address, size):
            #0x10 is way more than enough bytes to grab a single instruction
            ins_bytes = ql.mem.read(address, 0x10)
            try:                
                self.history.append(next(self.md.disasm(ins_bytes, address)))
            except StopIteration: 
                #if this ever happens, then the unicorn/qiling is going to crash because it tried to execute an instruction that it cant, so we are just not going to do anything
                pass

        self.history_hook_handle = self.ql.hook_block(__hook_block)

    def track_instruction_coverage(self) -> None:
        """Configures the history plugin to track all of the instructions that are executed. Removes any existing hooks
        
        Returns:
            None
        """
        if self.history_hook_handle:
            self.clear_hooks()

        def __hook_block(ql, address, size):
            #0x10 is way more than enough bytes to grab a single instruction
            ins_bytes = ql.mem.read(address, 0x10)
            try:                
                self.history.append(next(self.md.disasm(ins_bytes, address)))
            except StopIteration: 
                #if this ever happens, then the unicorn/qiling is going to crash because it tried to execute an instruction that it cant, so we are just not going to do anything
                pass

        self.history_hook_handle = self.ql.hook_code(__hook_block)

    def get_ins_only_lib(self, libs: List[str]) -> List[CsInsn]:
        """Returns a list of addresses that have been executed that are only in mmaps for objects that match the regex of items in the list
        
        Args:
            libs (List[str]): A list of regex strings to match against the library names in the memory maps

        Returns:
            List[capstone.CsInsn]: A list of CsInsn that have been executed and are only in the memory maps that match the regex

        Examples:
            >>> history.get_ins_only_lib([".*libc.so.*", ".*libpthread.so.*"])
        """    

        executable_maps = self.get_regex_matching_exec_maps(libs)
        
        return [x for x in self.history if any([x.address >= start and x.address <= end for start, end, _, _, _ in executable_maps])]

    def get_ins_exclude_lib(self, libs: List[str]) -> List[CsInsn]:
        '''Returns a list of history instructions that are not in the libraries that match the regex in the libs list
        
        Args:
            libs (List[str]): A list of regex strings to match against the library names in the memory maps
        
        Returns:
            List[capstone.CsInsn]: A list of CsInsn that have been executed and are not in the memory maps that match the regex

        Examples:
            >>> history.get_ins_exclude_lib([".*libc.so.*", ".*libpthread.so.*"])
        '''

        executable_maps = self.get_regex_matching_exec_maps(libs)
        return [h for h in self.history if not any(start <= h.address <= end for start, end, _, _, _ in executable_maps)]

    
    def get_mem_map_from_addr(self, ins) -> tuple:
        '''Returns the memory map that contains the instruction

        Args:
            ins: The instruction address to search for, can be either an int or a capstone.CsInsn

        Returns:
            tuple: A tuple that contains the memory map that contains the instruction
                this tuple is in the format of (start_addr, end_addr, perms, name, path)

        Examples: 
            >>> history.get_mem_map_from_addr(0x7ffff7dd1b97)
        '''

        if isinstance(ins, CsInsn):
            ins = ins.address

        assert isinstance(ins, int)

        #get the memory map that contains the instruction
        mem_map = [x for x in self.ql.mem.get_mapinfo() if x[0] <= ins and x[1] >= ins]

        if len(mem_map) == 0:
            return None

        # i sure hope theres not more than one map that contains the instruction lol
        return mem_map[0]

    def get_regex_matching_exec_maps(self, libs: List[str]) -> List:
        '''Returns a list of tuples for current mmaps whose names match the regex of libs in the list
        
        This is a wrapper around ql.mem.get_mapinfo() and just filters the results by the regex of the library names and also only returns maps that are executable

        Args:
            libs (List[str]): A list of regex strings to match against the library names in the memory maps

        Returns:
            List: A list of tuples that match the regex and are executable

        Examples:
            >>> history.get_regex_matching_exec_maps([".*libc.so.*", ".*libpthread.so.*"])
            >>> history.get_regex_matching_exec_maps(".*libc.*")
        '''

        # if libs is a string, convert it to a list
        if isinstance(libs, str):
            libs = [libs]

        # filter the history list by the library name, using a list of regex
        regex = [re.compile(lib) for lib in libs] 

        # filter the list of tuples 
        # so that we return only the ones where the library name matches the regex
        regex_matching_libs = [x for x in self.ql.mem.get_mapinfo() if any([r.match(x[3]) for r in regex])]

        # filter viable_libs for items that have the executable bit set
        executable_maps = [x for x in regex_matching_libs if 'x' in x[2]]

        return executable_maps