from __future__ import annotations
from typing import List, Tuple, TYPE_CHECKING, Union, Optional, Any

if TYPE_CHECKING:
    from qiling import Qiling
    from qiling.core_hooks_types import HookRet
    from capstone import Cs

import re
from capstone import CsInsn


class History:
    history_hook_handle: HookRet
    history: List[CsInsn] = []
    ql: Qiling
    md: Cs
    arm_is_thumb: bool

    def __init__(self, ql: Qiling) -> None:
        self.ql = ql
        self.md = self.ql.arch.disassembler
        self.arm_is_thumb = getattr(ql.arch, 'is_thumb', False)
        self.track_block_coverage()

    def clear_history(self) -> None:
        """Clears the current state of the history 
        
        """
        self.history.clear()

    def clear_hooks(self) -> None:
        """Clears the current history hook from the Qiling instance

        Returns:
            None 
        """

        self.ql.hook_del(self.history_hook_handle)

    def __hook_block(self, ql: Qiling, address: int, size: int) -> Any:
        '''
        The unicorn block/instruction hook function for the track_block_coverage and track_instruction_coverage functions. This just give us a way to append capstone objects to the history list
        '''

        # get the current state of the thumb mode, only applys to arm
        # originally we were going to access the ql.arch.disassembler directly for all architectures from in this callback, but in the
        # implementation for arch.arm.disassembler, the capstone instance is recreated every time (to make sure THUMB mode is properly dealt with)
        if self.arm_is_thumb is not getattr(ql.arch, "is_thumb", False):
            # the thumb mode has changed, so we need to update the disassembler
            self.arm_is_thumb = not self.arm_is_thumb
            self.md = self.ql.arch.disassembler

        # 0x10 is way more than enough bytes to grab a single instruction
        ins_bytes = ql.mem.read(address, 0x10)
        try:
            self.history.append(next(self.md.disasm(ins_bytes, address)))
        except StopIteration:
            # if this ever happens, then the unicorn/qiling is going to crash because it tried to execute 
            # an instruction that it cant, so we are just not going to do anything
            pass

    def track_block_coverage(self) -> None:
        """Configures the history plugin to track all of the basic blocks that are executed. Removes any existing hooks
        
        Returns:
            None
        """
        if getattr(self, 'history_hook_handle', None):
            self.clear_hooks()

        self.history_hook_handle = self.ql.hook_block(self.__hook_block)

    def track_instruction_coverage(self) -> None:
        """Configures the history plugin to track all of the instructions that are executed. Removes any existing hooks
        
        Returns:
            None
        """
        if getattr(self, 'history_hook_handle', None):
            self.clear_hooks()

        self.history_hook_handle = self.ql.hook_code(self.__hook_block)

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
        
        return [x for x in self.history if any(start <= x.address <= end for start, end, _, _, _ in executable_maps)]

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

    def get_mem_map_from_addr(self, ins: Union[int, CsInsn]) -> Optional[Tuple]:
        '''Returns the memory map that contains the instruction

        Args:
            ins (Union[int, CsInsn]): The instruction address to search for, can be either an int or a capstone.CsInsn

        Returns:
            Optional[Tuple]: A tuple that contains the memory map that contains the instruction
                this tuple is in the format of (start_addr, end_addr, perms, name, path)

        Examples: 
            >>> history.get_mem_map_from_addr(0x7ffff7dd1b97)
        '''

        if isinstance(ins, CsInsn):
            ins = ins.address

        assert isinstance(ins, int)

        return next((x for x in self.ql.mem.get_mapinfo() if x[0] <= ins and x[1] >= ins), None)

    def get_regex_matching_exec_maps(self, libs: List[str]) -> List[Tuple]:
        '''Returns a list of tuples for current mmaps whose names match the regex of libs in the list
        
        This is a wrapper around ql.mem.get_mapinfo() and just filters the results by the regex of the library names 
        and also only returns maps that are executable

        Args:
            libs (Union[str, Collection[str]]): A list of regex strings to match against the library names in the memory maps

        Returns:
            List[Tuple]: A list of tuples that match the regex and are executable

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
        regex_matching_libs = [x for x in self.ql.mem.get_mapinfo() if any(r.match(x[3]) for r in regex)]

        # filter viable_libs for items that have the executable bit set
        return [x for x in regex_matching_libs if 'x' in x[2]]
