"""ws-bridge.py: a browser-style WebSocket client on one side, a fake stratum
pool on the other; every text frame must arrive at the pool as one line and
every pool line must come back as one text frame. Standard library only."""
import asyncio
import base64
import importlib.util
import json
import os
import struct
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("ws-bridge.py")
SPEC = importlib.util.spec_from_file_location("ws_bridge", MODULE_PATH)
BRIDGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BRIDGE)


def client_frame(payload: bytes, opcode=0x1, fin=True) -> bytes:
    mask = os.urandom(4)
    head = bytes([(0x80 if fin else 0) | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack("!H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack("!Q", n)
    return head + mask + bytes(b ^ mask[i & 3] for i, b in enumerate(payload))


async def read_server_frame(reader):
    b1, b2 = await reader.readexactly(2)
    opcode, n = b1 & 0x0F, b2 & 0x7F
    assert not (b2 & 0x80), "server frames are never masked"
    if n == 126:
        n = struct.unpack("!H", await reader.readexactly(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", await reader.readexactly(8))[0]
    return opcode, await reader.readexactly(n)


class FakePool:
    """Echoes each line back as a stratum-looking result and pushes one notify."""
    def __init__(self):
        self.lines = []

    async def handle(self, reader, writer):
        writer.write(b'{"id":null,"method":"mining.notify","params":["job1"]}\n')
        await writer.drain()
        try:
            while True:
                line = await reader.readuntil(b"\n")
                self.lines.append(line)
                msg = json.loads(line)
                writer.write(json.dumps({"id": msg.get("id"), "result": True, "error": None}).encode() + b"\n")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()


class BridgeTests(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    async def _stack(self, origins=()):
        pool = FakePool()
        pool_srv = await asyncio.start_server(pool.handle, "127.0.0.1", 0, limit=BRIDGE.MAX_LINE)
        pp = pool_srv.sockets[0].getsockname()[1]
        bridge_srv = await asyncio.start_server(
            lambda r, w: BRIDGE.relay(r, w, "127.0.0.1", pp, set(origins)), "127.0.0.1", 0, limit=BRIDGE.MAX_LINE)
        bp = bridge_srv.sockets[0].getsockname()[1]
        return pool, pool_srv, bridge_srv, bp

    async def _open(self, port, origin="https://xcoinminer.com"):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        key = base64.b64encode(os.urandom(16)).decode()
        w.write((f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: {origin}\r\n\r\n").encode())
        await w.drain()
        head = await r.readuntil(b"\r\n\r\n")
        return r, w, head, key

    def test_handshake_and_round_trip(self):
        async def go():
            pool, ps, bs, bp = await self._stack()
            r, w, head, key = await self._open(bp)
            self.assertTrue(head.startswith(b"HTTP/1.1 101"))
            self.assertIn(BRIDGE.accept_key(key).encode(), head)
            op, data = await read_server_frame(r)                       # the pool's notify, one frame
            self.assertEqual(op, 0x1)
            self.assertEqual(json.loads(data)["method"], "mining.notify")
            w.write(client_frame(b'{"id":1,"method":"mining.subscribe","params":[]}'))
            await w.drain()
            op, data = await read_server_frame(r)
            self.assertEqual(json.loads(data), {"id": 1, "result": True, "error": None})
            self.assertEqual(pool.lines, [b'{"id":1,"method":"mining.subscribe","params":[]}\n'])
            w.write(client_frame(b"", 0x9))                             # ping -> pong
            await w.drain()
            op, data = await read_server_frame(r)
            self.assertEqual(op, 0xA)
            w.write(client_frame(struct.pack("!H", 1000), 0x8))          # close -> close echoed
            await w.drain()
            op, data = await read_server_frame(r)
            self.assertEqual(op, 0x8)
            w.close(); ps.close(); bs.close()
        self.run_async(go())

    def test_large_and_fragmented_messages(self):
        async def go():
            pool, ps, bs, bp = await self._stack()
            r, w, head, key = await self._open(bp)
            await read_server_frame(r)                                   # notify
            big = json.dumps({"id": 2, "method": "mining.submit", "params": ["x" * 70000]}).encode()
            w.write(client_frame(big))                                   # 64-bit length path
            await w.drain()
            op, data = await read_server_frame(r)
            self.assertEqual(json.loads(data)["id"], 2)
            self.assertEqual(pool.lines[-1], big + b"\n")
            msg = b'{"id":3,"method":"mining.authorize","params":["a.b"]}'
            w.write(client_frame(msg[:10], 0x1, fin=False) + client_frame(msg[10:], 0x0, fin=True))
            await w.drain()
            op, data = await read_server_frame(r)
            self.assertEqual(json.loads(data)["id"], 3)
            self.assertEqual(pool.lines[-1], msg + b"\n")
            w.close(); ps.close(); bs.close()
        self.run_async(go())

    def test_origin_allowlist_and_plain_http_probe(self):
        async def go():
            pool, ps, bs, bp = await self._stack(origins={"https://xcoinminer.com"})
            r, w, head, key = await self._open(bp, origin="https://evil.example")
            self.assertTrue(head.startswith(b"HTTP/1.1 403"))
            w.close()
            r, w, head, key = await self._open(bp)                       # allowed origin
            self.assertTrue(head.startswith(b"HTTP/1.1 101"))
            w.close()
            r, w = await asyncio.open_connection("127.0.0.1", bp)         # a health probe, no upgrade
            w.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); await w.drain()
            head = await r.readuntil(b"\r\n\r\n")
            self.assertTrue(head.startswith(b"HTTP/1.1 200"))
            body = await r.read()
            self.assertIn(b"stratum websocket ok", body)
            self.assertEqual(pool.lines, [])                             # never touched the pool
            w.close(); ps.close(); bs.close()
        self.run_async(go())

    def test_pool_down_closes_with_1011(self):
        async def go():
            bs = await asyncio.start_server(lambda r, w: BRIDGE.relay(r, w, "127.0.0.1", 1, set()), "127.0.0.1", 0)
            bp = bs.sockets[0].getsockname()[1]
            r, w, head, key = await self._open(bp)
            self.assertTrue(head.startswith(b"HTTP/1.1 101"))
            op, data = await read_server_frame(r)
            self.assertEqual(op, 0x8)
            self.assertEqual(struct.unpack("!H", data[:2])[0], 1011)
            w.close(); bs.close()
        self.run_async(go())


if __name__ == "__main__":
    unittest.main()
