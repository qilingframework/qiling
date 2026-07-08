#!/usr/bin/env python3
"""
Qiling MCP Server Tests

Test suite for Qiling Framework MCP Server implementation.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock
from qiling.mcp.server import QilingMCPServer
from qiling.mcp.tools import (
    load_binary,
    get_state,
    read_memory,
    write_memory,
    get_registers,
    set_registers,
    get_memory_map,
    start_emulation,
    stop_emulation,
    set_hook,
    list_hooks,
    remove_hook,
    get_context,
    reset_context,
)


@pytest.fixture
def mock_qiling():
    """Mock Qiling instance for testing."""
    with patch('qiling.mcp.tools.Qiling') as mock_ql_class:
        mock_ql = Mock()
        mock_ql_class.return_value = mock_ql
        
        # Mock arch
        mock_ql.arch = Mock()
        mock_ql.arch.type = Mock()
        mock_ql.arch.type.__str__ = Mock(return_value="X86")
        mock_ql.arch.bits = 32
        mock_ql.arch.endian = Mock()
        mock_ql.arch.endian.value = 1  # Little endian
        mock_ql.arch.regs = Mock()
        mock_ql.arch.regs.pc = 0x400000
        mock_ql.arch.regs.sp = 0x7fff0000
        mock_ql.arch.regs.eax = 0
        mock_ql.arch.regs.ebx = 0
        mock_ql.arch.register_mapping = {'pc': 0, 'sp': 1, 'eax': 2, 'ebx': 3}
        
        # Mock os
        mock_ql.os = Mock()
        mock_ql.os.type = Mock()
        mock_ql.os.type.__str__ = Mock(return_value="LINUX")
        
        # Mock loader
        mock_ql.loader = Mock()
        mock_ql.loader.entry_point = 0x400000
        
        # Mock memory
        mock_ql.mem = Mock()
        mock_ql.mem.read = Mock(return_value=b'\x90\x90\x90\x90')
        mock_ql.mem.write = Mock()
        mock_ql.mem.map_info = [
            (0x400000, 0x401000, 5, "code", None),  # r-x
            (0x7fff0000, 0x80000000, 3, "stack", None),  # rw-
        ]
        
        # Mock run/stop
        mock_ql.run = Mock()
        mock_ql.stop = Mock()
        mock_ql.exit_point = 0
        
        yield mock_ql


@pytest.mark.asyncio
async def test_load_binary(mock_qiling):
    """Test loading a binary."""
    result = await load_binary("/path/to/binary", "/path/to/rootfs")
    
    assert result["status"] == "success"
    assert "binary" in result
    assert result["binary"]["arch"] == "X86"
    assert result["binary"]["os"] == "LINUX"
    assert result["binary"]["bits"] == 32


@pytest.mark.asyncio
async def test_get_state(mock_qiling):
    """Test getting emulation state."""
    await load_binary("/path/to/binary", "/path/to/rootfs")
    result = await get_state()
    
    assert result["status"] == "success"
    assert "state" in result
    assert result["state"]["arch"] == "X86"
    assert result["state"]["pc"] == "0x400000"
    assert result["state"]["sp"] == "0x7fff0000"


@pytest.mark.asyncio
async def test_read_memory(mock_qiling):
    """Test reading memory."""
    await load_binary("/path/to/binary", "/path/to/rootfs")
    result = await read_memory(0x400000, 4)
    
    assert result["status"] == "success"
    assert result["address"] == "0x400000"
    assert result["size"] == 4
    assert result["data"] == "90909090"


@pytest.mark.asyncio
async def test_write_memory(mock_qiling):
    """Test writing memory."""
    await load_binary("/path/to/binary", "/path/to/rootfs")
    result = await write_memory(0x400000, "cc" * 4)
    
    assert result["status"] == "success"
    assert result["size"] == 4
    mock_qiling.mem.write.assert_called_once()


@pytest.mark.asyncio
async def test_get_registers(mock_qiling):
    """Test getting register values."""
    await load_binary("/path/to/binary", "/path/to/rootfs")
    result = await get_registers()
    
    assert result["status"] == "success"
    assert "registers" in result
    assert result["arch"] == "X86"
    assert result["bits"] == 32


@pytest.mark.asyncio
async def test_set_registers(mock_qiling):
    """Test setting register values."""
    await load_binary("/path/to/binary", "/path/to/rootfs")
    result = await set_registers({"eax": 0x1234, "ebx": "0x5678"})
    
    assert result["status"] == "success"
    assert result["set_count"] == 2


@pytest.mark.asyncio
async def test_get_memory_map(mock_qiling):
    """Test getting memory map."""
    await load_binary("/path/to/binary", "/path/to/rootfs")
    result = await get_memory_map()
    
    assert result["status"] == "success"
    assert "regions" in result
    assert result["count"] == 2
    assert result["regions"][0]["permissions"] == "r-x"
    assert result["regions"][1]["permissions"] == "rw-"


@pytest.mark.asyncio
async def test_start_emulation(mock_qiling):
    """Test starting emulation."""
    await load_binary("/path/to/binary", "/path/to/rootfs")
    result = await start_emulation()
    
    assert result["status"] == "success"
    mock_qiling.run.assert_called_once()


@pytest.mark.asyncio
async def test_stop_emulation(mock_qiling):
    """Test stopping emulation."""
    await load_binary("/path/to/binary", "/path/to/rootfs")
    await start_emulation()
    result = await stop_emulation()
    
    assert result["status"] == "success"
    mock_qiling.stop.assert_called_once()


@pytest.mark.asyncio
async def test_set_hook(mock_qiling):
    """Test setting a hook."""
    await load_binary("/path/to/binary", "/path/to/rootfs")
    result = await set_hook(0x400000, "code", "my_callback")
    
    assert result["status"] == "success"
    assert "hook" in result
    assert result["hook"]["address"] == "0x400000"
    assert result["hook"]["type"] == "code"


@pytest.mark.asyncio
async def test_list_hooks(mock_qiling):
    """Test listing hooks."""
    await load_binary("/path/to/binary", "/path/to/rootfs")
    await set_hook(0x400000, "code")
    result = await list_hooks()
    
    assert result["status"] == "success"
    assert result["count"] == 1


@pytest.mark.asyncio
async def test_remove_hook(mock_qiling):
    """Test removing a hook."""
    await load_binary("/path/to/binary", "/path/to/rootfs")
    hook_result = await set_hook(0x400000, "code")
    hook_id = hook_result["hook"]["id"]
    
    result = await remove_hook(hook_id)
    assert result["status"] == "success"
    
    # Verify hook is removed
    list_result = await list_hooks()
    assert list_result["count"] == 0


@pytest.mark.asyncio
async def test_server_initialize():
    """Test server initialization."""
    server = QilingMCPServer()
    result = await server.initialize()
    
    assert result["name"] == "qiling-mcp"
    assert result["version"] == "0.1.0"
    assert "tools" in result["capabilities"]


@pytest.mark.asyncio
async def test_server_list_tools():
    """Test listing tools."""
    server = QilingMCPServer()
    result = await server.list_tools()
    
    assert result["status"] == "success"
    assert "tools" in result
    assert result["count"] > 0


@pytest.mark.asyncio
async def test_server_call_tool(mock_qiling):
    """Test calling a tool through server."""
    server = QilingMCPServer()
    result = await server.call_tool("load_binary", {
        "binary_path": "/path/to/binary",
        "rootfs": "/path/to/rootfs"
    })
    
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_server_call_unknown_tool():
    """Test calling an unknown tool."""
    server = QilingMCPServer()
    result = await server.call_tool("unknown_tool", {})
    
    assert result["status"] == "error"
    assert "not found" in result["message"]


def test_context_management():
    """Test context management."""
    reset_context()
    ctx = get_context()
    assert ctx is not None
    assert ctx.ql is None
    assert ctx.running is False
    
    reset_context()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
