"""Send an allowlisted action to the local temporary authentication debugger."""
import argparse
import asyncio
import json

from apple_probe import PRIVATE


async def main(action):
    reader, writer = await asyncio.open_unix_connection(str(PRIVATE / "auth.sock"))
    writer.write((json.dumps({"action": action}) + "\n").encode())
    await writer.drain()
    print((await reader.readline()).decode().strip())
    writer.close()
    await writer.wait_closed()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["status", "login", "refresh", "request-code", "verify", "replay-code", "delegate", "stop"])
    asyncio.run(main(parser.parse_args().action))
