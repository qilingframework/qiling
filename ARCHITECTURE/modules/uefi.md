---
eatmycode_version: "2.0.0"
---

# UEFI Services

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/os/uefi/, DXE/SMM service tables, protocols, events or UEFI module execution.

## Responsibility and Status

Owns UEFI service/API behavior, protocol definitions, DXE/SMM contexts and
firmware events/callbacks. **In progress:** two direct UEFI integration tests
pass; they do not establish complete firmware or SMM conformance. The UEFI
PE loader owns mapping, service-table installation and module queues.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [uefi.py](../../qiling/os/uefi/uefi.py): `QlOsUefi` | Calls, module callbacks, execution and selected OS state |
| [fncc.py](../../qiling/os/uefi/fncc.py): `dxeapi` | Typed service hooks and interception |
| [context.py](../../qiling/os/uefi/context.py): `DxeContext`, `SmmContext` | Context-owned heaps, protocols and configuration state |
| [bs.py](../../qiling/os/uefi/bs.py), [rt.py](../../qiling/os/uefi/rt.py), [ds.py](../../qiling/os/uefi/ds.py), [smst.py](../../qiling/os/uefi/smst.py), [smm.py](../../qiling/os/uefi/smm.py), [protocols/](../../qiling/os/uefi/protocols/) | Service tables, SMM environment and protocol hooks |
| [UefiSpec.py](../../qiling/os/uefi/UefiSpec.py), [ProcessorBind.py](../../qiling/os/uefi/ProcessorBind.py), [guids.csv](../../qiling/os/uefi/guids.csv), [__init__.py](../../qiling/os/uefi/__init__.py) | ABI types and GUID names |
| [test_uefi.py](../../tests/test_uefi.py), [qiling/profiles/uefi.ql](../../qiling/profiles/uefi.ql) | API interception and sanitized heap integration |

## Local Conventions

The [root baseline](../../ARCHITECTURE.md#code-conventions) applies; retain
specification casing and ordered ctypes fields. Service handlers use
`dxeapi` and explicit parameter types. `type64.py` is reference-only and
raises on import; do not use it as runtime definitions. No reproducible
regeneration pipeline for that reference file is established; runtime
layout changes belong in the actual spec/bindings/protocol definitions.

## Contracts and Invariants

- Function calls use cdecl for 32-bit and ms64 for 64-bit state. Service
  hooks resolve by function name; `set_api` adapts user targets, and the
  decorator applies CALL/ENTER/EXIT hooks (`uefi.py`, `fncc.py`).
- Context protocols and heaps are initialized with the PE/UEFI loader.
  Preserve DXE versus SMM context selection, GUID identity, native-width
  fields and protocol callback signatures.
- Module-enter/module-exit callbacks can thwart subsequent execution;
  queue/event/notification state and saved heap state live partly in the
  loader. `QlOsUefi.save()` only extends base state with its entry point.
- Guest structure addresses and buffer lengths must be validated before
  shared memory/heap access. A handler stub returning success is not proof
  of specification conformance.

## Dependencies and Boundaries

Read [loaders](loaders.md) for image queues/context installation/snapshots,
[OS base](os-base.md) for struct/fcall/heap changes, [arch](arch.md) for ABI
width, and [extensions](extensions.md) when sanitizer/coverage hooks change.
UEFI shares PE parsing infrastructure, not Windows API semantics.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Service/protocol | Descriptor layout, decorator, GUID and context | Direct UEFI script plus target service assertions |
| Event/module scheduling | Queue notifications, loader context callbacks | Read loader; module order/interception regression |
| SMM or snapshot | OS/loader state split and context memory | Read loader and OS base; explicit restoration/state evidence |

## Verification

From `tests/`: **`python test_uefi.py`** with root dependencies and
`examples/rootfs/x8664_efi` fixtures. Both tests passed during rebuild;
they exercise interception and sanitized heap behavior. Do not substitute
`python -m unittest test_uefi`: actual bodies are guarded by `__main__`.
For package/coverage output changes also use the CLI coverage test through
[extensions](extensions.md).

## Known Gaps

Coverage is narrow relative to the service/protocol surface. Full SMM,
32-bit firmware and complete state restoration were not verified.
`type64.py` is an intentionally unusable reference artifact, not a second
supported runtime ABI. Keep unimplemented service behavior explicit.
