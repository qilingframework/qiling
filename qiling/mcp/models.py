"""
Data models for Qiling MCP Server

These models define the structured output format for MCP tools,
ensuring consistent JSON responses for AI Agent consumption.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EmulationState:
    """Binary emulation state."""
    arch: str
    os: str
    entry_point: int = 0
    exit_point: int = 0
    pc: int = 0
    sp: int = 0
    registers: Dict[str, int] = field(default_factory=dict)
    running: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "arch": self.arch,
            "os": self.os,
            "entry_point": hex(self.entry_point),
            "exit_point": hex(self.exit_point),
            "pc": hex(self.pc),
            "sp": hex(self.sp),
            "registers": {k: hex(v) for k, v in self.registers.items()},
            "running": self.running,
        }


@dataclass
class MemoryRegion:
    """Memory region information."""
    start: int
    end: int
    size: int
    permissions: str
    name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": hex(self.start),
            "end": hex(self.end),
            "size": self.size,
            "permissions": self.permissions,
            "name": self.name,
        }


@dataclass
class MemoryContent:
    """Memory content with hex and ASCII representation."""
    address: int
    data: bytes
    ascii_repr: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "hex": self.data.hex(),
            "ascii": self.ascii_repr,
            "size": len(self.data),
        }


@dataclass
class SyscallInfo:
    """System call information."""
    number: int
    name: str
    params: List[Any] = field(default_factory=list)
    retval: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "number": self.number,
            "name": self.name,
            "params": self.params,
            "retval": hex(self.retval) if self.retval is not None else None,
        }


@dataclass
class BinaryInfo:
    """Binary file information."""
    path: str
    arch: str
    os: str
    endian: str
    bits: int
    entry_point: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "arch": self.arch,
            "os": self.os,
            "endian": self.endian,
            "bits": self.bits,
            "entry_point": hex(self.entry_point),
        }


@dataclass
class ExecutionResult:
    """Execution result."""
    success: bool
    exit_code: Optional[int] = None
    error: str = ""
    instructions_executed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "error": self.error,
            "instructions_executed": self.instructions_executed,
        }


@dataclass
class HookInfo:
    """Hook information."""
    hook_type: str
    address: int
    callback: str
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hook_type": self.hook_type,
            "address": hex(self.address),
            "callback": self.callback,
            "enabled": self.enabled,
        }


@dataclass
class CommandResult:
    """Command execution result."""
    output: str = ""
    error: str = ""
    return_code: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "output": self.output,
            "error": self.error,
            "return_code": self.return_code,
        }
