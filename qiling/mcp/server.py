#!/usr/bin/env python3
"""
Qiling MCP Server

Main server implementation for Qiling Framework MCP integration.
Provides Model Context Protocol interface for AI Agents to interact with
the Qiling binary emulation framework.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any, Dict, List, Optional

from .tools import TOOL_REGISTRY
from .models import EmulationState, MemoryRegion, BinaryInfo, HookInfo

logger = logging.getLogger(__name__)


class QilingMCPServer:
    """Qiling MCP Server implementation."""

    def __init__(self, name: str = "qiling-mcp", version: str = "0.1.0"):
        self.name = name
        self.version = version
        self.tools = TOOL_REGISTRY
        logger.info(f"Initialized {name} v{version}")

    async def initialize(self) -> Dict[str, Any]:
        """Initialize the MCP server.
        
        Returns:
            Server capabilities and information
        """
        return {
            "name": self.name,
            "version": self.version,
            "capabilities": {
                "tools": list(self.tools.keys()),
            },
            "description": "Qiling Framework MCP Server for binary emulation",
        }

    async def list_tools(self) -> Dict[str, Any]:
        """List all available tools.
        
        Returns:
            Dictionary containing tool definitions
        """
        tool_list = []
        
        for name, tool_def in self.tools.items():
            tool_info = {
                "name": name,
                "description": tool_def["description"],
                "parameters": tool_def["parameters"],
            }
            tool_list.append(tool_info)
        
        return {
            "status": "success",
            "tools": tool_list,
            "count": len(tool_list),
        }

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a specific tool with arguments.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Arguments to pass to the tool
            
        Returns:
            Tool execution result
        """
        if tool_name not in self.tools:
            return {
                "status": "error",
                "message": f"Tool '{tool_name}' not found"
            }
        
        tool_def = self.tools[tool_name]
        tool_func = tool_def["function"]
        
        try:
            # Call the tool function
            result = await tool_func(**arguments)
            return result
            
        except Exception as e:
            logger.error(f"Tool '{tool_name}' execution failed: {e}")
            return {
                "status": "error",
                "message": f"Tool execution failed: {str(e)}"
            }

    async def shutdown(self) -> None:
        """Shutdown the MCP server and cleanup resources."""
        from .tools import reset_context
        reset_context()
        logger.info("Server shutdown complete")


async def run_server(
    transport: str = "stdio",
    host: str = "localhost",
    port: int = 8000,
) -> None:
    """Run the Qiling MCP server.
    
    Args:
        transport: Transport type (stdio, sse, http)
        host: Host address for network transports
        port: Port number for network transports
    """
    server = QilingMCPServer()
    
    try:
        if transport == "stdio":
            await run_stdio_server(server)
        elif transport == "sse":
            await run_sse_server(server, host, port)
        elif transport == "http":
            await run_http_server(server, host, port)
        else:
            raise ValueError(f"Unsupported transport: {transport}")
            
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
    finally:
        await server.shutdown()


async def run_stdio_server(server: QilingMCPServer) -> None:
    """Run server with stdio transport.
    
    Args:
        server: MCP server instance
    """
    import json
    
    logger.info("Starting stdio transport")
    
    # Initialize server
    init_result = await server.initialize()
    
    # Send initialization response
    print(json.dumps({
        "jsonrpc": "2.0",
        "method": "initialize",
        "result": init_result,
    }))
    sys.stdout.flush()
    
    # Main message loop
    while True:
        try:
            # Read JSON-RPC message from stdin
            line = sys.stdin.readline()
            if not line:
                break
            
            message = json.loads(line.strip())
            
            # Handle different message types
            method = message.get("method")
            params = message.get("params", {})
            request_id = message.get("id")
            
            if method == "tools/list":
                result = await server.list_tools()
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                result = await server.call_tool(tool_name, arguments)
            else:
                result = {
                    "status": "error",
                    "message": f"Unknown method: {method}"
                }
            
            # Send response
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": result,
            }
            
            print(json.dumps(response))
            sys.stdout.flush()
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            continue
        except Exception as e:
            logger.error(f"Message handling error: {e}")
            continue


async def run_sse_server(
    server: QilingMCPServer,
    host: str,
    port: int,
) -> None:
    """Run server with SSE transport.
    
    Args:
        server: MCP server instance
        host: Host address
        port: Port number
    """
    try:
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
        import uvicorn
        
        app = FastAPI(title="Qiling MCP Server")
        
        @app.post("/mcp")
        async def mcp_endpoint(request: Request):
            body = await request.json()
            method = body.get("method")
            params = body.get("params", {})
            
            if method == "tools/list":
                result = await server.list_tools()
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                result = await server.call_tool(tool_name, arguments)
            else:
                result = {
                    "status": "error",
                    "message": f"Unknown method: {method}"
                }
            
            return JSONResponse(content=result)
        
        logger.info(f"Starting SSE server on {host}:{port}")
        config = uvicorn.Config(app, host=host, port=port, log_level="info")
        uvicorn_server = uvicorn.Server(config)
        await uvicorn_server.serve()
        
    except ImportError as e:
        logger.error(f"SSE transport requires fastapi and uvicorn: {e}")
        raise


async def run_http_server(
    server: QilingMCPServer,
    host: str,
    port: int,
) -> None:
    """Run server with HTTP transport.
    
    Args:
        server: MCP server instance
        host: Host address
        port: Port number
    """
    # HTTP transport uses the same implementation as SSE
    await run_sse_server(server, host, port)


def main():
    """Main entry point for the Qiling MCP server."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Qiling MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http"],
        default="stdio",
        help="Transport type (default: stdio)"
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Host address for network transports (default: localhost)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port number for network transports (default: 8000)"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)"
    )
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    
    # Run server
    asyncio.run(run_server(
        transport=args.transport,
        host=args.host,
        port=args.port,
    ))


if __name__ == "__main__":
    main()
