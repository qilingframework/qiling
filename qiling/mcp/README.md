# Qiling MCP Server

Model Context Protocol (MCP) Server implementation for [Qiling Framework](https://github.com/qilingframework/qiling), enabling AI Agents to programmatically interact with the Qiling binary emulation framework.

## Overview

This MCP Server provides a standardized interface for AI Agents to:
- Load and initialize binary files for emulation
- Read/write memory contents
- Get/set CPU register values
- Control emulation execution (start/stop)
- Set execution hooks for debugging
- Query memory maps and emulation state

## Features

- **12 MCP Tools**: Comprehensive binary emulation control
- **Multiple Transport Support**: stdio, SSE, HTTP
- **Structured JSON Output**: All tools return well-defined JSON responses
- **Context Management**: Global state management for emulation sessions
- **Test Coverage**: Complete test suite with mocks

## Installation

```bash
# Install Qiling Framework first
pip install qiling

# Install MCP Server dependencies (optional, for SSE/HTTP transport)
pip install fastapi uvicorn
```

## Usage

### Command Line

```bash
# Start with stdio transport (default)
python -m qiling.mcp.server

# Start with SSE transport
python -m qiling.mcp.server --transport sse --host localhost --port 8000

# Start with HTTP transport
python -m qiling.mcp.server --transport http --host 0.0.0.0 --port 8000
```

### Python API

```python
import asyncio
from qiling.mcp.server import QilingMCPServer

async def main():
    server = QilingMCPServer()
    
    # Initialize server
    init_result = await server.initialize()
    print(f"Server: {init_result['name']} v{init_result['version']}")
    
    # List available tools
    tools = await server.list_tools()
    print(f"Available tools: {tools['count']}")
    
    # Load a binary
    result = await server.call_tool("load_binary", {
        "binary_path": "/path/to/binary",
        "rootfs": "/path/to/rootfs"
    })
    
    # Read memory
    mem = await server.call_tool("read_memory", {
        "address": 0x400000,
        "size": 16
    })
    
    # Get registers
    regs = await server.call_tool("get_registers", {})
    print(f"PC: {regs['registers']['pc']}")

asyncio.run(main())
```

## Available Tools

### Binary Management

#### `load_binary`
Load and initialize a binary for emulation.

**Parameters:**
- `binary_path` (string, required): Path to the binary file
- `rootfs` (string, optional): Path to root filesystem (default: ".")
- `verbose` (string, optional): Log level - DISABLED/OFF/DEFAULT/DEBUG/DISASM/DUMP (default: "DEFAULT")

**Returns:** Binary information including architecture, OS, entry point

#### `get_state`
Get current emulation state.

**Parameters:** None

**Returns:** Current PC, SP, registers, and running status

### Memory Operations

#### `read_memory`
Read memory contents at specified address.

**Parameters:**
- `address` (integer, required): Memory address (hex or int)
- `size` (integer, required): Number of bytes to read

**Returns:** Memory contents as hex string and byte array

#### `write_memory`
Write data to memory at specified address.

**Parameters:**
- `address` (integer, required): Memory address (hex or int)
- `data` (string, required): Hex string of bytes to write

**Returns:** Write operation result

#### `get_memory_map`
Get memory map showing all mapped regions.

**Parameters:** None

**Returns:** List of memory regions with start/end addresses, permissions, and names

### Register Operations

#### `get_registers`
Get current register values.

**Parameters:** None

**Returns:** Dictionary of all register names and their values (hex format)

#### `set_registers`
Set register values.

**Parameters:**
- `registers` (object, required): Dictionary mapping register names to values

**Returns:** Number of registers successfully set

### Execution Control

#### `start_emulation`
Start binary emulation.

**Parameters:**
- `begin` (integer, optional): Start address (None for entry point)
- `end` (integer, optional): End address (None for default)
- `timeout` (integer, optional): Timeout in milliseconds (0 for no timeout)
- `count` (integer, optional): Number of instructions to execute (0 for unlimited)

**Returns:** Emulation result with final state

#### `stop_emulation`
Stop running emulation.

**Parameters:** None

**Returns:** Stop operation result

### Hook Management

#### `set_hook`
Set execution hook at specified address.

**Parameters:**
- `address` (integer, required): Address to set hook at (hex or int)
- `hook_type` (string, optional): Type of hook - code/memory_read/memory_write/interrupt (default: "code")
- `callback_name` (string, optional): Name for the callback function

**Returns:** Hook information with ID

#### `list_hooks`
List all active hooks.

**Parameters:** None

**Returns:** List of active hooks

#### `remove_hook`
Remove a hook by ID.

**Parameters:**
- `hook_id` (string, required): ID of the hook to remove

**Returns:** Removal result

## MCP Protocol

This server implements the Model Context Protocol (MCP) specification:

- **JSON-RPC 2.0**: Standard message format
- **Tool Discovery**: `tools/list` method
- **Tool Invocation**: `tools/call` method
- **Structured Responses**: All responses include status and data

### Example JSON-RPC Messages

**List tools:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

**Call tool:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "load_binary",
    "arguments": {
      "binary_path": "/path/to/binary",
      "rootfs": "/path/to/rootfs"
    }
  }
}
```

## Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest qiling/mcp/test_server.py -v
```

## Architecture

```
qiling/mcp/
├── __init__.py       # Module entry point
├── models.py         # Data models (EmulationState, MemoryRegion, etc.)
├── tools.py          # MCP tool implementations
├── server.py         # MCP server and transport handlers
├── test_server.py    # Test suite
└── README.md         # This file
```

## Use Cases

1. **CTF Challenge Analysis**: AI Agents can load and analyze CTF binaries
2. **Malware Analysis**: Safe emulation of suspicious binaries
3. **Exploit Development**: Test and debug exploits in controlled environment
4. **Binary Reverse Engineering**: Automated analysis of binary behavior
5. **Security Research**: Programmatic binary analysis at scale

## Requirements

- Python 3.8+
- Qiling Framework 2.0+
- Optional: FastAPI + Uvicorn (for SSE/HTTP transport)

## License

This MCP Server implementation follows the same license as Qiling Framework (GPL-2.0).

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows existing style
- New tools include tests
- Documentation is updated

## References

- [Qiling Framework](https://github.com/qilingframework/qiling)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [MCP Specification](https://spec.modelcontextprotocol.io/)
