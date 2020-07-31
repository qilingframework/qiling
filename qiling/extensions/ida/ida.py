import idc
import ida_ua
import ida_idaapi
import ida_funcs
import ida_nalt
import idautils
import ida_xref
import ida_kernwin
import ida_ida
import ida_bytes
import ida_segment
import ida_name
import ida_gdl
import ida_frame

class IDA:
    def __init__(self):
        pass
    
    @staticmethod
    def get_function(addr):
        return ida_funcs.get_func(addr)
    
    @staticmethod
    def get_function_start(addr):
        return IDA.get_function(addr).start_ea

    @staticmethod
    def get_function_end(addr):
        return IDA.get_function(addr).end_ea
    
    @staticmethod
    def get_function_framesize(addr):
        return IDA.get_function(addr).frsize

    @staticmethod
    def get_function_name(addr):
        return ida_funcs.get_func_name(addr)

    @staticmethod
    def get_functions():
        return [IDA.get_function(func) for func in idautils.Functions()]

    # note:
    # corresponds to IDA graph view
    # a good example to iterate the graph
    # https://github.com/idapython/src/blob/bc9b51b1c70083815a574a57b7a783698de3698d/examples/core/dump_flowchart.py
    # arg can be a function or a (start, end) tuple or an address in the function
    @staticmethod
    def get_flowchart(arg):
        if type(arg) is int:
            func = IDA.get_function(arg)
            if func is None:
                return None
            return ida_gdl.FlowChart(func)
        return ida_gdl.FlowChart(arg)

    @staticmethod
    def block_is_terminating(bb):
        # fcb_ret: has a retn instruction in the end
        # fcb_noret: in most cases, exit() is called
        # fcb_indjump: jmp $eax
        if (bb.type == ida_gdl.fcb_ret or bb.type == ida_gdl.fcb_noret or
                (bb.type == ida_gdl.fcb_indjump and len(list(bb.succs())) == 0)):
            return True
        for b in bb.succs():
            if b.type == ida_gdl.fcb_extern:
                return True
        return False

    @staticmethod
    def get_starting_block(addr):
        flowchart = IDA.get_flowchart(addr)
        if flowchart is None:
            return None
        func = IDA.get_function(addr)
        for bb in flowchart:
            if bb.start_ea == func.start_ea:
                return bb
        return None
    
    @staticmethod
    def get_terminating_blocks(addr):
        flowchart = IDA.get_flowchart(addr)
        return [bb for bb in flowchart if IDA.block_is_terminating(bb)]

    @staticmethod
    def get_segments():
        r = []
        seg = ida_segment.get_first_seg()
        while seg is not None:
            r.append(seg)
            seg = ida_segment.get_next_seg(seg.start_ea)
        return r
    
    @staticmethod
    def get_segment_name(s):
        return ida_segment.get_segm_name(s)

    @staticmethod
    def get_segment_by_name(name):
        return ida_segment.get_segm_by_name(name)
    
    @staticmethod
    def __addr_in_seg(addr):
        segs = IDA.get_segments()
        for seg in segs:
            if addr < seg.end_ea and addr >= seg.start_ea:
                return seg
        return None

    # note: accept name and address in the segment
    @staticmethod
    def get_segment(arg):
        if type(arg) is int:
            return IDA.__addr_in_seg(arg)
        else: # str
            return IDA.get_segment_by_name(arg)

    @staticmethod
    def get_segment_start(arg):
        seg = IDA.get_segment(arg)
        if seg is not None:
            return seg.start_ea
        return None
    
    @staticmethod
    def get_segment_end(arg):
        seg = IDA.get_segment(arg)
        if seg is not None:
            return seg.end_ea
        return None

    @staticmethod
    def get_segment_perm(arg):
        seg = IDA.get_segment(arg)
        if seg is not None:
            return seg.perm # RWX e.g. 0b101 = R + X
        return None
    
    @staticmethod
    def get_segment_type(arg):
        seg = IDA.get_segment(arg)
        if seg is not None:
            return seg.type # 0x1 SEG_DATA 0x2 SEG_CODE See doc for details
        return None

    @staticmethod
    def get_instruction(addr):
        r = ida_ua.print_insn_mnem(addr)
        if r == "":
            return None
        return r

    @staticmethod
    def get_operand(addr, n):
        return (idc.get_operand_type(addr, n), idc.get_operand_value(addr, n))

    @staticmethod
    def get_name(addr):
        return ida_name.get_name(addr)
    
    @staticmethod
    def get_name_address(name, addr=0):
        return ida_name.get_name_ea(addr, name)

    @staticmethod
    def get_bytes(addr, l):
        return ida_bytes.get_bytes(addr, l)

    @staticmethod
    def get_byte(addr):
        return ida_bytes.get_byte(addr)

    @staticmethod
    def get_word(addr):
        return ida_bytes.get_word(addr)

    @staticmethod
    def get_dword(addr):
        return ida_bytes.get_dword(addr)
    
    @staticmethod
    def get_qword(addr):
        return ida_bytes.get_qword(addr)

    @staticmethod
    def get_xrefsto(addr, flags=ida_xref.XREF_ALL):
        return [ref.frm for ref in idautils.XrefsTo(addr, flags)]

    @staticmethod
    def get_xrefsfrom(addr, flags=ida_xref.XREF_ALL):
        return [ref.frm for ref in idautils.XrefsFrom(addr, flags)]

    @staticmethod
    def get_input_file_path():
        return ida_nalt.get_input_file_path()
    
    @staticmethod
    def get_info_structure():
        return ida_idaapi.get_inf_structure()

    @staticmethod
    def get_main_address():
        return IDA.get_info_structure().main
    
    @staticmethod
    def get_max_address():
        return IDA.get_info_structure().max_ea
    
    @staticmethod
    def get_min_address():
        return IDA.get_info_structure().min_ea

    @staticmethod
    def is_big_endian():
        return IDA.get_info_structure().is_be()

    @staticmethod
    def is_little_endian():
        return not IDA.is_big_endian()

    @staticmethod
    def get_filetype():
        info = IDA.get_info_structure()
        ftype = info.filetype
        if ftype == ida_ida.f_MACHO:
            return "macho"
        elif ftype == ida_ida.f_PE or ftype == ida_ida.f_EXE or ftype == ida_ida.f_EXE_old: # is this correct?
            return "pe"
        elif ftype == ida_ida.f_ELF:
            return "elf"
        else:
            return None

    @staticmethod
    def get_ql_arch_string():
        info = IDA.get_info_structure()
        proc = info.get_procName()
        result = None
        if proc == "metapc":
            result = "x86"
            if info.is_64bit():
                result = "x8664"
        elif "mips" in proc:
            result = "mips"
        elif "arm" in proc:
            result = "arm32"
            if info.is_64bit():
                result = "arm64"
        # That's all we support :(
        return result
    
    @staticmethod
    def get_current_address():
        return ida_kernwin.get_screen_ea()

    # return (?, start, end)
    @staticmethod
    def get_last_selection():
        return ida_kernwin.read_range_selection(None)
    
    # Use with skipcalls
    # note that the address is the end of target instruction
    # e.g.:
    # 0x1 push eax
    # 0x4 mov eax, 0
    # call get_frame_sp_delta(0x4) and get -4.
    @staticmethod
    def get_frame_sp_delta(addr):
        return ida_frame.get_sp_delta(IDA.get_function(addr), addr)