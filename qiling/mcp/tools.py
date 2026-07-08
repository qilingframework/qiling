#!/usr/bin/env python3
"""
Qiling MCP Tools Implementation

This module implements the core MCP tools for Qiling Framework integration,
providing programmatic access to binary emulation capabilities.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass

from .models import (
    EmulationState,
    MemoryRegion,
    BinaryInfo,
    HookInfo,
)

logger = logging.getLogger(__name__)


@dataclass
class QilingContext:
    """Context for managing Qiling emulation state."""
    ql: Optional[Any] = None
    binary_path: Optional[str] = None
    rootfs: Optional[str] = None
    hooks: Dict[str, HookInfo] = {}
    running: bool = False


# Global context manager
_context: Optional[QilingContext] = None


def get_context() -> QilingContext:
    """Get or create the global Qiling context."""
    global _context
    if _context is None:
        _context = QilingContext()
    return _context


def reset_context() -> None:
    """Reset the global Qiling context."""
    global _context
    if _context and _context.ql and _context.running:
        try:
            _context.ql.stop()
        except Exception:
            pass
    _context = QilingContext()


async def load_binary(
    binary_path: str,
    rootfs: str = ".",
    verbose: str = "DEFAULT",
    **kwargs: Any
) -> Dict[str, Any]:
    """Load and initialize a binary for emulation.
    
    Args:
        binary_path: Path to the binary file to emulate
        rootfs: Path to the root filesystem for the emulation
        verbose: Logging verbosity level (DISABLED, OFF, DEFAULT, DEBUG, DISASM, DUMP)
        **kwargs: Additional arguments passed to Qiling constructor
        
    Returns:
        Dictionary containing binary information and emulation state
    """
    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
        
        # Map verbose string to enum
        verbose_map = {
            "DISABLED": QL_VERBOSE.DISABLED,
            "OFF": QL_VERBOSE.OFF,
            "DEFAULT": QL_VERBOSE.DEFAULT,
            "DEBUG": QL_VERBOSE.DEBUG,
            "DISASM": QL_VERBOSE.DISASM,
            "DUMP": QL_VERBOSE.DUMP,
        }
        verbose_level = verbose_map.get(verbose.upper(), QL_VERBOSE.DEFAULT)
        
        # Reset any existing context
        reset_context()
        
        # Create new context
        ctx = get_context()
        ctx.binary_path = binary_path
        ctx.rootfs = rootfs
        
        # Prepare arguments
        argv = [binary_path]
        ql_args = {
            "argv": argv,
            "rootfs": rootfs,
            "verbose": verbose_level,
        }
        ql_args.update(kwargs)
        
        # Initialize Qiling instance
        ctx.ql = Qiling(**ql_args)
        
        # Extract binary information
        binary_info = BinaryInfo(
            path=binary_path,
            arch=str(ctx.ql.arch.type),
            os=str(ctx.ql.os.type),
            endian="little" if ctx.ql.arch.endian.value == 1 else "big",
            bits=ctx.ql.arch.bits,
            entry_point=ctx.ql.loader.entry_point if hasattr(ctx.ql.loader, 'entry_point') else 0,
        )
        
        logger.info(f"Loaded binary: {binary_path} ({binary_info.arch}/{binary_info.os})")
        
        return {
            "status": "success",
            "binary": binary_info.to_dict(),
            "message": f"Binary loaded successfully: {binary_path}"
        }
        
    except Exception as e:
        logger.error(f"Failed to load binary: {e}")
        return {
            "status": "error",
            "message": f"Failed to load binary: {str(e)}"
        }


async def get_state() -> Dict[str, Any]:
    """Get current emulation state.
    
    Returns:
        Dictionary containing current emulation state including registers, PC, SP
    """
    ctx = get_context()
    
    if ctx.ql is None:
        return {
            "status": "error",
            "message": "No binary loaded. Call load_binary first."
        }
    
    try:
        # Get register values
        registers = {}
        if hasattr(ctx.ql.arch, 'registers'):
            for reg_name in ctx.ql.arch.register_mapping.keys():
                try:
                    value = getattr(ctx.ql.arch.regs, reg_name, None)
                    if value is not None:
                        registers[reg_name] = value
                except Exception:
                    pass
        
        # Get PC and SP
        pc = getattr(ctx.ql.arch.regs, 'pc', 0)
        sp = getattr(ctx.ql.arch.regs, 'sp', 0)
        
        state = EmulationState(
            arch=str(ctx.ql.arch.type),
            os=str(ctx.ql.os.type),
            entry_point=ctx.ql.loader.entry_point if hasattr(ctx.ql.loader, 'entry_point') else 0,
            exit_point=ctx.ql.exit_point or 0,
            pc=pc,
            sp=sp,
            registers=registers,
            running=ctx.running,
        )
        
        return {
            "status": "success",
            "state": state.to_dict()
        }
        
    except Exception as e:
        logger.error(f"Failed to get state: {e}")
        return {
            "status": "error",
            "message": f"Failed to get state: {str(e)}"
        }


async def read_memory(address: int, size: int) -> Dict[str, Any]:
    """Read memory contents at specified address.
    
    Args:
        address: Memory address to read from (hex or int)
        size: Number of bytes to read
        
    Returns:
        Dictionary containing memory contents as hex string and metadata
    """
    ctx = get_context()
    
    if ctx.ql is None:
        return {
            "status": "error",
            "message": "No binary loaded. Call load_binary first."
        }
    
    try:
        # Convert hex string to int if needed
        if isinstance(address, str):
            address = int(address, 16)
        
        # Read memory
        data = ctx.ql.mem.read(address, size)
        
        return {
            "status": "success",
            "address": hex(address),
            "size": size,
            "data": data.hex(),
            "data_bytes": list(data),
        }
        
    except Exception as e:
        logger.error(f"Failed to read memory: {e}")
        return {
            "status": "error",
            "message": f"Failed to read memory at {hex(address)}: {str(e)}"
        }


async def write_memory(address: int, data: str) -> Dict[str, Any]:
    """Write data to memory at specified address.
    
    Args:
        address: Memory address to write to (hex or int)
        data: Hex string of bytes to write
        
    Returns:
        Dictionary containing write operation result
    """
    ctx = get_context()
    
    if ctx.ql is None:
        return {
            "status": "error",
            "message": "No binary loaded. Call load_binary first."
        }
    
    try:
        # Convert hex string to int if needed
        if isinstance(address, str):
            address = int(address, 16)
        
        # Convert hex string to bytes
        if isinstance(data, str):
            data_bytes = bytes.fromhex(data)
        else:
            data_bytes = data
        
        # Write memory
        ctx.ql.mem.write(address, data_bytes)
        
        return {
            "status": "success",
            "address": hex(address),
            "size": len(data_bytes),
            "message": f"Successfully wrote {len(data_bytes)} bytes to {hex(address)}"
        }
        
    except Exception as e:
        logger.error(f"Failed to write memory: {e}")
        return {
            "status": "error",
            "message": f"Failed to write memory at {hex(address)}: {str(e)}"
        }


async def get_registers() -> Dict[str, Any]:
    """Get current register values.
    
    Returns:
        Dictionary containing all register names and their values
    """
    ctx = get_context()
    
    if ctx.ql is None:
        return {
            "status": "error",
            "message": "No binary loaded. Call load_binary first."
        }
    
    try:
        registers = {}
        
        # Get all register values
        if hasattr(ctx.ql.arch, 'registers'):
            for reg_name in ctx.ql.arch.register_mapping.keys():
                try:
                    value = getattr(ctx.ql.arch.regs, reg_name, None)
                    if value is not None:
                        registers[reg_name] = hex(value)
                except Exception:
                    pass
        
        return {
            "status": "success",
            "registers": registers,
            "arch": str(ctx.ql.arch.type),
            "bits": ctx.ql.arch.bits,
        }
        
    except Exception as e:
        logger.error(f"Failed to get registers: {e}")
        return {
            "status": "error",
            "message": f"Failed to get registers: {str(e)}"
        }


async def set_registers(registers: Dict[str, int]) -> Dict[str, Any]:
    """Set register values.
    
    Args:
        registers: Dictionary mapping register names to values (hex strings or ints)
        
    Returns:
        Dictionary containing operation result
    """
    ctx = get_context()
    
    if ctx.ql is None:
        return {
            "status": "error",
            "message": "No binary loaded. Call load_binary first."
        }
    
    try:
        set_count = 0
        
        for reg_name, value in registers.items():
            # Convert hex string to int if needed
            if isinstance(value, str):
                value = int(value, 16)
            
            # Set register value
            if hasattr(ctx.ql.arch.regs, reg_name):
                setattr(ctx.ql.arch.regs, reg_name, value)
                set_count += 1
            else:
                logger.warning(f"Register {reg_name} not found")
        
        return {
            "status": "success",
            "set_count": set_count,
            "message": f"Successfully set {set_count} registers"
        }
        
    except Exception as e:
        logger.error(f"Failed to set registers: {e}")
        return {
            "status": "error",
            "message": f"Failed to set registers: {str(e)}"
        }


async def get_memory_map() -> Dict[str, Any]:
    """Get memory map showing all mapped regions.
    
    Returns:
        Dictionary containing list of memory regions with their properties
    """
    ctx = get_context()
    
    if ctx.ql is None:
        return {
            "status": "error",
            "message": "No binary loaded. Call load_binary first."
        }
    
    try:
        regions = []
        
        # Get memory map from Qiling
        if hasattr(ctx.ql.mem, 'map_info'):
            for entry in ctx.ql.mem.map_info:
                start, end, perms, name, _ = entry
                
                # Convert permissions to string
                perm_str = ""
                perm_str += "r" if (perms & 1) else "-"
                perm_str += "w" if (perms & 2) else "-"
                perm_str += "x" if (perms & 4) else "-"
                
                region = MemoryRegion(
                    start=start,
                    end=end,
                    size=end - start,
                    permissions=perm_str,
                    name=name,
                )
                regions.append(region.to_dict())
        
        return {
            "status": "success",
            "regions": regions,
            "count": len(regions),
        }
        
    except Exception as e:
        logger.error(f"Failed to get memory map: {e}")
        return {
            "status": "error",
            "message": f"Failed to get memory map: {str(e)}"
        }


async def start_emulation(
    begin: Optional[int] = None,
    end: Optional[int] = None,
    timeout: int = 0,
    count: int = 0,
) -> Dict[str, Any]:
    """Start binary emulation.
    
    Args:
        begin: Start address (None for entry point)
        end: End address (None for default)
        timeout: Timeout in milliseconds (0 for no timeout)
        count: Number of instructions to execute (0 for unlimited)
        
    Returns:
        Dictionary containing emulation result
    """
    ctx = get_context()
    
    if ctx.ql is None:
        return {
            "status": "error",
            "message": "No binary loaded. Call load_binary first."
        }
    
    if ctx.running:
        return {
            "status": "error",
            "message": "Emulation already running"
        }
    
    try:
        ctx.running = True
        
        # Set emulation parameters
        if begin is not None:
            ctx.ql.entry_point = begin
        if end is not None:
            ctx.ql.exit_point = end
        ctx.ql.timeout = timeout
        ctx.ql.count = count
        
        # Start emulation
        ctx.ql.run()
        
        ctx.running = False
        
        return {
            "status": "success",
            "message": "Emulation completed",
            "final_state": (await get_state())["state"] if ctx.ql else None,
        }
        
    except Exception as e:
        ctx.running = False
        logger.error(f"Emulation failed: {e}")
        return {
            "status": "error",
            "message": f"Emulation failed: {str(e)}"
        }


async def stop_emulation() -> Dict[str, Any]:
    """Stop running emulation.
    
    Returns:
        Dictionary containing stop operation result
    """
    ctx = get_context()
    
    if ctx.ql is None:
        return {
            "status": "error",
            "message": "No binary loaded"
        }
    
    if not ctx.running:
        return {
            "status": "error",
            "message": "Emulation not running"
        }
    
    try:
        ctx.ql.stop()
        ctx.running = False
        
        return {
            "status": "success",
            "message": "Emulation stopped"
        }
        
    except Exception as e:
        logger.error(f"Failed to stop emulation: {e}")
        return {
            "status": "error",
            "message": f"Failed to stop emulation: {str(e)}"
        }


async def set_hook(
    address: int,
    hook_type: str = "code",
    callback_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Set execution hook at specified address.
    
    Args:
        address: Address to set hook at (hex or int)
        hook_type: Type of hook (code, memory_read, memory_write, interrupt)
        callback_name: Optional name for the callback function
        
    Returns:
        Dictionary containing hook information
    """
    ctx = get_context()
    
    if ctx.ql is None:
        return {
            "status": "error",
            "message": "No binary loaded. Call load_binary first."
        }
    
    try:
        # Convert hex string to int if needed
        if isinstance(address, str):
            address = int(address, 16)
        
        hook_id = f"hook_{address}_{hook_type}"
        
        # Create hook info
        hook_info = HookInfo(
            id=hook_id,
            address=address,
            type=hook_type,
            callback=callback_name or f"callback_{hook_id}",
        )
        
        ctx.hooks[hook_id] = hook_info
        
        return {
            "status": "success",
            "hook": hook_info.to_dict(),
            "message": f"Hook set at {hex(address)}"
        }
        
    except Exception as e:
        logger.error(f"Failed to set hook: {e}")
        return {
            "status": "error",
            "message": f"Failed to set hook: {str(e)}"
        }


async def list_hooks() -> Dict[str, Any]:
    """List all active hooks.
    
    Returns:
        Dictionary containing list of active hooks
    """
    ctx = get_context()
    
    if ctx.ql is None:
        return {
            "status": "error",
            "message": "No binary loaded"
        }
    
    try:
        hooks = [hook.to_dict() for hook in ctx.hooks.values()]
        
        return {
            "status": "success",
            "hooks": hooks,
            "count": len(hooks),
        }
        
    except Exception as e:
        logger.error(f"Failed to list hooks: {e}")
        return {
            "status": "error",
            "message": f"Failed to list hooks: {str(e)}"
        }


async def remove_hook(hook_id: str) -> Dict[str, Any]:
    """Remove a hook by ID.
    
    Args:
        hook_id: ID of the hook to remove
        
    Returns:
        Dictionary containing removal result
    """
    ctx = get_context()
    
    if ctx.ql is None:
        return {
            "status": "error",
            "message": "No binary loaded"
        }
    
    try:
        if hook_id in ctx.hooks:
            del ctx.hooks[hook_id]
            return {
                "status": "success",
                "message": f"Hook {hook_id} removed"
            }
        else:
            return {
                "status": "error",
                "message": f"Hook {hook_id} not found"
            }
        
    except Exception as e:
        logger.error(f"Failed to remove hook: {e}")
        return {
            "status": "error",
            "message": f"Failed to remove hook: {str(e)}"
        }


# Tool registry for MCP server
TOOL_REGISTRY = {
    "load_binary": {
        "function": load_binary,
        "description": "Load and initialize a binary for emulation",
        "parameters": {
            "binary_path": {"type": "string", "required": True},
            "rootfs": {"type": "string", "required": False, "default": "."},
            "verbose": {"type": "string", "required": False, "default": "DEFAULT"},
        }
    },
    "get_state": {
        "function": get_state,
        "description": "Get current emulation state",
        "parameters": {}
    },
    "read_memory": {
        "function": read_memory,
        "description": "Read memory contents at specified address",
        "parameters": {
            "address": {"type": "integer", "required": True},
            "size": {"type": "integer", "required": True},
        }
    },
    "write_memory": {
        "function": write_memory,
        "description": "Write data to memory at specified address",
        "parameters": {
            "address": {"type": "integer", "required": True},
            "data": {"type": "string", "required": True},
        }
    },
    "get_registers": {
        "function": get_registers,
        "description": "Get current register values",
        "parameters": {}
    },
    "set_registers": {
        "function": set_registers,
        "description": "Set register values",
        "parameters": {
            "registers": {"type": "object", "required": True},
        }
    },
    "get_memory_map": {
        "function": get_memory_map,
        "description": "Get memory map showing all mapped regions",
        "parameters": {}
    },
    "start_emulation": {
        "function": start_emulation,
        "description": "Start binary emulation",
        "parameters": {
            "begin": {"type": "integer", "required": False},
            "end": {"type": "integer", "required": False},
            "timeout": {"type": "integer", "required": False, "default": 0},
            "count": {"type": "integer", "required": False, "default": 0},
        }
    },
    "stop_emulation": {
        "function": stop_emulation,
        "description": "Stop running emulation",
        "parameters": {}
    },
    "set_hook": {
        "function": set_hook,
        "description": "Set execution hook at specified address",
        "parameters": {
            "address": {"type": "integer", "required": True},
            "hook_type": {"type": "string", "required": False, "default": "code"},
            "callback_name": {"type": "string", "required": False},
        }
    },
    "list_hooks": {
        "function": list_hooks,
        "description": "List all active hooks",
        "parameters": {}
    },
    "remove_hook": {
        "function": remove_hook,
        "description": "Remove a hook by ID",
        "parameters": {
            "hook_id": {"type": "string", "required": True},
        }
    },
}


__all__ = [
    "TOOL_REGISTRY",
    "QilingContext",
    "get_context",
    "reset_context",
    "load_binary",
    "get_state",
    "read_memory",
    "write_memory",
    "get_registers",
    "set_registers",
    "get_memory_map",
    "start_emulation",
    "stop_emulation",
    "set_hook",
    "list_hooks",
    "remove_hook",
]
