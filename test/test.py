from mcp import ClientSession
from mcp.client.sse import sse_client

async def main():
    endpoint = "http://13.201.22.227:8000/sse"  # replace this with your actual endpoint

    async with sse_client(endpoint) as streams:
        async with ClientSession(*streams) as session:  # removed the *
            await session.initialize()
            tools_result = await session.list_tools()
            print(tools_result)

# Then somewhere else:
import asyncio
asyncio.run(main())
