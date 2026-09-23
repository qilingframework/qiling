---
eatmycode_version: "2.1.0"
---

# DOS and BIOS Interrupts

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/os/dos/, DOS/BIOS interrupt leaves, terminal behavior or DOS file/disk semantics.

## Responsibility and Status

Owns DOS/BIOS interrupt behavior, DOS handles, terminal state and run-loop
semantics. **In progress:** the direct DOS sample test passes; EXE/MBR,
interactive display and full interrupt coverage are unverified. DOS image
loading and shared disk/file abstractions are separate owners.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [dos.py](../../qiling/os/dos/dos.py): `QlOsDos`, `Flags` | Interrupt interception, flags, terminal lifetime and execution |
| [interrupts/__init__.py](../../qiling/os/dos/interrupts/__init__.py) | Interrupt-number handler registry |
| [interrupts/](../../qiling/os/dos/interrupts/) | BIOS/DOS leaf implementations, console, disk and file services |
| [utils.py](../../qiling/os/dos/utils.py) | DOS-specific helpers |
| [test_dos.py](../../tests/test_dos.py), [test_dos_exe.py](../../tests/test_dos_exe.py), [profiles/dos.ql](../../qiling/profiles/dos.ql) | Program/format samples and consumed DOS settings |

## Local Conventions

[Root conventions](../../ARCHITECTURE.md#code-conventions) suffice. Preserve
interrupt identifiers and guest register names, including AH/AL leaves;
return status may live in carry/zero flags and registers rather than a
Python return value. Handler names mirror interrupt numbers. Curses is a
host dependency; Windows uses the manifest's platform-marked curses package.

## Contracts and Invariants

- Each interrupt builds `(intno, AH)` for user CALL/ENTER/EXIT lookup.
  Built-ins are selected by interrupt number and handle their own leaves.
  ENTER/EXIT callbacks receive `ql`; unsupported interrupt numbers raise
  `NotImplementedError` (`QlOsDos.hook_syscall`).
- `run()` uses the loader's `start_address` unless explicitly overridden,
  applies exit overrides and catches/re-raises Unicorn errors after logging.
  The implementation's binary path is distinct from shellcode behavior.
- DOS file handles belong to this personality; segment:offset arithmetic
  uses real-mode address conventions. Do not treat these handles or far
  pointers as host descriptors/addresses.
- `KERNEL.version` and `ticks_per_second` are read from the DOS profile.
  Curses terminal setup requires an appropriate terminal; destructor cleanup
  restores it when initialized. Preserve screen/keyboard state lifetime.
- Disk and filesystem handlers reach shared host-backed objects; changes to
  guest offsets/lengths must keep host access within intended resources.

## Dependencies and Boundaries

Read [loaders](loaders.md) for COM/EXE/MBR layout and initial registers,
[arch](arch.md) for 8086 registers/segmentation, and [OS base](os-base.md)
for `disk.py`, paths and file objects. Windows/UEFI API dispatch rules do
not apply to DOS interrupt leaves.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Interrupt/leaf | Registry, AH handling, flags and override callbacks | DOS regression for the changed register/flag contract |
| Program startup | Start address, segment registers, loader format | Read loaders/arch; matching EXE/COM test |
| Console/file/disk | Curses lifetime, handle/offset validation | Read OS base for shared changes; relevant device/fixture test |

## Verification

From `tests/`: `python -m unittest test_dos` passed one program test during
the latest refresh with the existing DOS rootfs fixture. Use
`python test_dos_exe.py` for EXE-loader changes; it was not part of the verified subset. Terminal
cases need usable curses/TTY support. A successful sample does not certify
all BIOS services or error leaves.

## Known Gaps

Interrupt coverage is incremental; unsupported leaves must remain explicit.
Interactive console, EXE/MBR and complete DOS-state recovery were not
verified. File/disk behavior requires both guest-register and host-resource
checks; don't infer containment solely from emulated execution.
