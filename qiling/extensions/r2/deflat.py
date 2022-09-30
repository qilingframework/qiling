from typing import TYPE_CHECKING, List, Optional

from qiling.const import QL_VERBOSE
from qiling.core import Qiling

if TYPE_CHECKING:
    from .r2 import R2, BasicBlock, Instruction


class R2Deflator:
    def __init__(self, r2: "R2", verbose=QL_VERBOSE.DISABLED) -> None:
        self.r2 = r2
        self.ql = r2.ql
        self.verbose = verbose

    @property
    def arch(self):
        return self.qlemu.arch.type.name.lower()

    def parse_blocks_for_deobf(self, addr: Optional[int] = None):
        addr = addr or self.r2.offset
        self.bbs = self.r2.get_fcn_bbs(addr)
        self.bb_mapping = {bb.addr: bb for bb in self.bbs}
        self.pre_dispatcher = max(
            self.bb_mapping.values(), key=lambda bb: bb.inputs)
        try:
            self.dispatcher = self.bb_mapping[self.pre_dispatcher.jump]
            self.first_block = self.bbs[0]
        except IndexError:
            self.ql.log.error("Fail to get dispatcher and first_block.")
            return
        self.real_blocks : List[BasicBlock]= []
        self.fake_blocks : List[BasicBlock]= []
        self.retn_blocks : List[BasicBlock]= []
        for bb in self.bbs:
            if self.pre_dispatcher.addr in (bb.jump, bb.fail) and bb.ninstr > 1:
                self.real_blocks.append(bb)
            elif (bb.jump or bb.fail) is None:  # block_is_terminating
                self.retn_blocks.append(bb)
            elif bb != self.first_block and bb != self.pre_dispatcher and bb != self.dispatcher:
                self.fake_blocks.append(bb)
        self.ql.log.info(f"First block: {self.first_block}")
        self.ql.log.info(f"Dispatcher: {self.dispatcher}")
        self.ql.log.info(f"Pre dispatcher: {self.pre_dispatcher}")
        self.ql.log.info(f"Real blocks:")
        for b in self.real_blocks:
            print(b)
        self.ql.log.info(f"Fake blocks: {self.fake_blocks}")
        self.ql.log.info(f"Return blocks: {self.retn_blocks}")

    def create_emu(self, ql: Qiling, *args, **kwargs):
        ql = Qiling(ql.argv, ql.rootfs, verbose=self.verbose, env=ql.env, *args, **kwargs)
        self.qlemu = ql
        return ql

    def _get_jcond_ins(self, bb: "BasicBlock") -> Optional["Instruction"]:
        res = []
        for ins in bb:
            if ins.is_jcond():
                res.append(ins)
        if len(res) > 1:
            self.ql.log.warning(f"More than one conditional jmp detected at {bb}")
        elif len(res) == 0:
            self.ql.log.warning(f"No conditional jmp found at {bb}")
            return None
        return res[0]

    def _force_cond(self, ql: Qiling, addr: int):
        '''addr: should be a conditional instruction'''
        analop = self.r2.anal_op(addr)
        if analop.type in ('cmov', 'mov'):  # FIXME: other conditional instructions?
            dst = analop.operands[0]
            if dst.type == 'reg':
                k = dst.value
            else:  # FIXME: when dst is not reg?
                return False
            src = analop.operands[1]
            if src.type == 'reg':
                v = ql.arch.regs.read(src.value)
            elif src.type == 'imm':
                v = src.value
            else:   # FIXME: when src is mem?
                return False
        self.ql.log.info(f"Force set {k} to {hex(v)}")
        ql.arch.regs.__setattr__(k, v)
        return True

    def _guide_hook(self, ql: Qiling, addr: int, size: int):
        start_bb = self.hook_data['startbb']
        func = self.hook_data['func']
        if addr not in func:
            ql.log.error(f"Address {hex(addr)} out of function boundaries!")
            ql.emu_stop()
            self.hook_data['result'] = False
            return
        cur_bb = self.r2.get_bb_at(addr)
        if "force" in self.hook_data and addr in self.hook_data['force']:
            if self.hook_data['force'][addr]:  # is True
                ql.log.info(f"Force execution at cond branch {hex(addr)}")
                result = self._force_cond(ql, addr)
                if not result:
                    ql.log.error(f"Fail to force conditional execution by r2anal at {hex(addr)}, stop now...")
                    self.hook_data['result'] = False
                    ql.emu_stop()
                    return
            next_addr = addr + size
            ql.log.info(f"Goto {hex(next_addr)} after branch...")
            ql.arch.regs.arch_pc = next_addr
        # TODO: Maybe we can detect whether the program will access unmapped
        #       here so that we won't map the memory.
        analop = self.r2.anal_op(addr)
        if analop.type == 'call':
            ql.arch.regs.arch_pc += analop.size
            return
        if start_bb == cur_bb:
            return
        if cur_bb in self.real_blocks or cur_bb in self.retn_blocks:
            if cur_bb not in self.paths[start_bb]:
                self.paths[start_bb].append(cur_bb)
            ql.emu_stop()

    def _search_path(self):
        self.paths = {bb: [] for bb in self.bbs}
        reals = [self.first_block, *self.real_blocks]
        ql = self.create_emu(self.ql)
        # set up stack before we really run.
        ql.run(begin=self.first_block.start_ea, end=self.first_block.end_ea, count=0xFFF)
        # okay, we can set up our core hook now.
        self.hook_data = None
        ql.hook_code(self._guide_hook)
        for bb in reals:
            ql.log.debug(f"Search control flow for block: {bb}")
            braddr = self._find_branch_in_block(bb)
            self.hook_data = {
                "startbb": bb,
                "func": self.r2.get_fcn_at(self.first_block.addr),
                "result": True,
            }
            ql_bb_start_ea = bb.addr
            ctx = ql.save()
            # Skip force execution in the first block.
            # `end=0` is a workaround for ql remembering last exit_point.
            if braddr is None or bb == self.first_block:
                ql.run(begin=ql_bb_start_ea, end=0, count=0xFFF)
            else:
                self.hook_data['force'] = {braddr: True}
                ql.run(begin=ql_bb_start_ea, end=0, count=0xFFF)
                ql.restore(ctx)
                if not self.hook_data['result']:
                    return False
                self.hook_data['force'] = {braddr: False}
                ql.run(begin=ql_bb_start_ea, end=0, count=0xFFF)
            ql.restore(ctx)
            if not self.hook_data['result']:
                return False
        self._log_paths_str()
        return True

    def _find_branch_in_block(self, bb: "BasicBlock") -> Optional[int]:
        insts = self.r2.dis(bb)
        for inst in insts:
            if inst.is_jcond():
                return inst.offset
        return None

    def _log_paths_str(self):
        for bb, succs in self.paths.items():
            if len(succs) == 1:
                self.ql.log.info(f"{bb} -> {succs[0]}")
            elif len(succs) == 2:
                self.ql.log.info(f"{bb} --(force jump)--> {succs[0]}")
                self.ql.log.info(f"|----(skip jump)----> {succs[1]}")
            elif len(succs) > 2:
                self.ql.log.warning(f"succs: {succs} found from {bb}!")

    def _asm(self, *args, **kwargs):
        self.ks = self.qlemu.arch.assembler
        return self.ks.asm(*args, **kwargs)

    # Patching microcode is TOO complex.
    # I would rahter write another 1e10 llvm passes than a single hexrays decompiler pass.
    def _arch_jmp_instruction(self, addr):
        arch = self.arch
        op = None
        if "x86" in arch:
            op = "jmp"
        elif "arm" in arch:
            op = "B"
        elif "mips" in arch:
            op = "j"
        return f"{op} {addr}"

        # See comments above.
    def _arch_cond_jmp_instruction(self, cond, addr):
        arch = self.arch
        op = None
        if "x86" in arch:
            op = f"j{cond}"
        elif "arm" in arch:
            op = f"b{cond}"
        elif "mips" in arch:
            op = f"j{cond}"
        return f"{op} {addr}"

    # See comments above.
    def _arch_parse_cond_from_addr(self, braddr):
        arch = self.arch
        analop = self.r2.anal_op(braddr)
        instr = analop.mnemonic
        if "x86" in arch: # cmovge
            return instr[4:]
        elif "arm" in arch:
            if instr.startswith("it"): # itt eq
                tks = instr.split(" ")
                if len(tks) != 2:
                    self.ql.log.error(f"Can't get condition from {instr}")
                    return None
                return tks[-1]
            elif "csel" in instr:
                return analop.operands[3].value
        # TODO: mips
        return None

    def _patch_bytes(self, start: int, bs: bytes):
        self.r2.write(start, bs)
        # self.r2._cmd(f"aaa @ {start}")  # seems no need to force analysis

    def _arch_branchj_patch(self, braddr: int, bb: "BasicBlock"):
        force_addr = self.paths[bb][0].addr
        normal_addr = self.paths[bb][1].addr
        # Temporary dirty fix.
        # See comments for _force_execution_by_parsing_assembly.
        if "arm64" == self.arch:
            force_addr, normal_addr = normal_addr, force_addr
        # Parse condition before patching nop.
        cond = self._arch_parse_cond_from_addr(braddr)
        buffer = [0] * (bb.end_ea - braddr)
        instr_to_assemble = self._arch_cond_jmp_instruction(cond, f"{hex(force_addr)}h")
        self.ql.log.info(f"Assemble {instr_to_assemble} at {hex(force_addr)}")
        bs1, _ = self._asm(instr_to_assemble, braddr)
        buffer[:len(bs1)] = bs1
        next_instr_address = braddr + len(bs1)
        instr_to_assemble = self._arch_jmp_instruction(f"{hex(normal_addr)}h")
        self.ql.log.info(f"Assemble {instr_to_assemble} at {hex(normal_addr)}")
        bs2, _ = self._asm(instr_to_assemble, next_instr_address)
        buffer[len(bs1):len(bs1) + len(bs2)] = bs2
        self.ql.log.info(f"Patch real block with branch from {hex(braddr)} to {hex(bb.end_ea)}")
        self._patch_bytes(braddr, bytes(buffer))

    def _patch_codes(self):
        if len(self.paths[self.first_block]) != 1:
            self.ql.log.error(f"Found wrong ways in first block: {self.first_block}, should be 1 path but get {len(self.paths[self.first_block])}, exit.")
            return
        self.ql.log.info("NOP dispatcher block")
        dispatcher_bb = self.dispatcher
        # Some notes:
        #    Patching b'\x00' instead of 'nop' can help IDA decompile a better result. Don't know why...
        #    Besides
        buffer = [0] * (dispatcher_bb.end_ea - dispatcher_bb.start_ea)
        first_jmp_addr = dispatcher_bb.start_ea
        instr_to_assemble = self._arch_jmp_instruction(f"{hex(self.paths[self.first_block][0].addr)}h")
        self.ql.log.info(f"Assemble {instr_to_assemble} at {hex(first_jmp_addr)}")
        bs, _ = self._asm(instr_to_assemble, first_jmp_addr)
        buffer[:len(bs)] = bs
        self.ql.log.info(f"Patch first jump at {hex(first_jmp_addr)}")
        self._patch_bytes(first_jmp_addr, bytes(buffer))
        for bb in self.real_blocks:
            self.ql.log.debug(f"Patching real block: {bb}")
            braddr = self._find_branch_in_block(bb)
            if braddr is None:
                last_instr_address = self.r2.dis(bb)[-1].offset
                buffer = [0x90] * (bb.end_ea - last_instr_address)
                if len(self.paths[bb]) != 1:
                    self.ql.log.warning(f"Found wrong ways in block: {bb}, should be 1 path but get {len(self.paths[bb])}")
                    continue
                instr_to_assemble = self._arch_jmp_instruction(f"{hex(self.paths[bb][0].addr)}h")
                self.ql.log.info(f"Assemble {instr_to_assemble} at {hex(last_instr_address)}")
                bs, _ = self._asm(instr_to_assemble, last_instr_address)
                buffer[:len(bs)] = bs
                self.ql.log.info(f"Patch real block from {hex(last_instr_address)} to {hex(bb.end_ea)}")
                self._patch_bytes(last_instr_address, bytes(buffer))
            else:
                if len(self.paths[bb]) != 2:
                    self.ql.log.warning(f"Found wrong ways in block: {bb}, should be 2 paths but get {len(self.paths[bb])}")
                    continue
                self._arch_branchj_patch(braddr, bb)
        for bb in self.fake_blocks:
            self.ql.log.info(f"Patch NOP for block: {bb}")
            self._patch_bytes(bb.start_ea, b"\x00"*(bb.end_ea-bb.start_ea))
        self.ql.log.info(f"Patch NOP for pre_dispatcher.")
        bb = self.pre_dispatcher
        self._patch_bytes(bb.start_ea, b"\x00"*(bb.end_ea-bb.start_ea))