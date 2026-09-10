#!/usr/bin/env python3
"""Emulate a raw AArch64 code-range blob with UDF trapping.

Maps a code blob (e.g. one architecture range extracted from a hybrid
image) as executable in an AArch64 session with a scratch stack and a
stub page standing in for loader-populated tables. Invalid instructions
surface as structured UDF faults (immediate logged, never skipped);
unmapped accesses stop at the loader-table boundary.

Usage: qiling_aarch64_chpe.py <blob> <load-addr-hex> [max-steps]
"""
import struct
import sys
from pathlib import Path

STUB_ADDR = 0x70000000
STACK_TOP = 0x100000000


def u32(mem_read, addr):
    return struct.unpack("<I", bytes(mem_read(addr, 4)))[0]


def main() -> int:
    from qiling import Qiling
    from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE

    if len(sys.argv) < 3:
        print("usage: qiling_aarch64_chpe.py <blob> <load-addr-hex> [max-steps]")
        return 2
    code = Path(sys.argv[1]).read_bytes()
    load_at = int(sys.argv[2], 16)
    max_steps = int(sys.argv[3]) if len(sys.argv) > 3 else 4096

    ql = Qiling(code=code, archtype=QL_ARCH.AARCH64, ostype=QL_OS.BLOB,
                profile="blob_raw.ql", verbose=QL_VERBOSE.OFF)
    ql.mem.map(load_at, (len(code) + 0xFFF) & ~0xFFF)
    ql.mem.write(load_at, code)
    ql.mem.map(STUB_ADDR, 0x1000)
    ql.mem.write(STUB_ADDR, b"\x00\x00\x00\x00")  # UDF landing pad
    ql.mem.map(STACK_TOP - 0x4000, 0x4000)

    events: list = []
    state = {"steps": 0}

    def hook_code(ql_inner):
        state["steps"] += 1
        if state["steps"] >= max_steps:
            events.append({"type": "STEP-CAP", "steps": state["steps"]})
            ql_inner.emu_stop()

    def hook_unmapped(ql_inner, access, addr, size, value):
        events.append({"type": "UNMAPPED", "pc": hex(ql_inner.arch.regs.pc),
                       "addr": hex(addr), "size": size})
        return False

    ql.hook_code(hook_code)
    ql.hook_mem_unmapped(hook_unmapped)

    ql.arch.regs.sp = STACK_TOP - 0x100
    try:
        ql.run(begin=load_at, end=load_at + len(code), count=max_steps)
        events.append({"type": "RETURNED", "steps": state["steps"]})
    except Exception as exc:
        pc = ql.arch.regs.pc
        try:
            word = u32(ql.mem.read, pc)
        except Exception:
            events.append({"type": "STOP", "pc": hex(pc),
                           "detail": f"{type(exc).__name__}: {exc}"})
        else:
            # True UDF (D42...) and zero-top-half padding share the logger.
            imm = word & 0xFFFF if (word & 0xFFFF0000) == 0 else (word >> 5) & 0xFFFF
            events.append({"type": "UDF", "pc": hex(pc),
                           "imm": hex(imm), "word": hex(word)})
    print(f"blob={sys.argv[1]} load={hex(load_at)} steps={state['steps']} events={events}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
