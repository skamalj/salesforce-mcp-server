from typing import Any, Dict, List, Optional
from mcp import ClientSession
from mcp.client.sse import sse_client


async with sse_client(self.endpoint) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                print(tools_result)