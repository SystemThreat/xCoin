#!/usr/bin/env python3
"""ws-bridge.py: stratum-over-WebSocket for the browser miner.

The pool speaks newline-delimited JSON over plain TCP (stratum). A browser can
only open WebSockets, so this relay accepts a WebSocket on --listen, opens one
TCP connection to --pool per client, and forwards text frames as lines and
lines as text frames. It adds nothing: no parsing of the stratum messages, no
authentication, no state. Standard library only, like the pool.

  python3 ws-bridge.py --listen 127.0.0.1:3336 --pool 127.0.0.1:3335 --origin https://xcoinminer.com

Put it behind a TLS terminator (a Cloudflare tunnel ingress pointing at
http://127.0.0.1:3336) and publish the wss:// URL in pool.js POOL_WSS. The
--origin allowlist (repeatable) refuses browsers from other sites; an empty
list allows any origin.
"""
import argparse
import asyncio
import base64
import hashlib
import logging
import os
import struct

log = logging.getLogger("ws-bridge")
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_FRAME = 4 * 1024 * 1024      # a mining.notify with a big coinbase is well under this
MAX_LINE = 4 * 1024 * 1024


def accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()


def encode_frame(payload: bytes, opcode: int = 0x1) -> bytes:
    """Server-to-client frame: FIN set, never masked."""
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack("!H", n)
    else:
        head += bytes([127]) + struct.pack("!Q", n)
    return head + payload


async def read_frame(reader: asyncio.StreamReader):
    """One client frame -> (opcode, payload). Client frames must be masked (RFC 6455 5.1)."""
    b1, b2 = await reader.readexactly(2)
    fin, opcode = b1 & 0x80, b1 & 0x0F
    masked, n = b2 & 0x80, b2 & 0x7F
    if not masked:
        raise ConnectionError("unmasked client frame")
    if n == 126:
        n = struct.unpack("!H", await reader.readexactly(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", await reader.readexactly(8))[0]
    if n > MAX_FRAME:
        raise ConnectionError("frame too large")
    mask = await reader.readexactly(4)
    data = bytearray(await reader.readexactly(n))
    for i in range(n):
        data[i] ^= mask[i & 3]
    if not fin:
        # Continuation frames: gather until FIN. Stratum messages are small; keep it simple.
        while True:
            c1, c2 = await reader.readexactly(2)
            cfin, cn = c1 & 0x80, c2 & 0x7F
            if cn == 126:
                cn = struct.unpack("!H", await reader.readexactly(2))[0]
            elif cn == 127:
                cn = struct.unpack("!Q", await reader.readexactly(8))[0]
            if len(data) + cn > MAX_FRAME:
                raise ConnectionError("message too large")
            cmask = await reader.readexactly(4)
            chunk = bytearray(await reader.readexactly(cn))
            for i in range(cn):
                chunk[i] ^= cmask[i & 3]
            data += chunk
            if cfin:
                break
    return opcode, bytes(data)


async def handshake(reader, writer, origins):
    request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    lines = request.decode("latin-1").split("\r\n")
    head = lines[0].split(" ")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    if len(head) < 2 or head[0] != "GET":
        raise ConnectionError("not a GET")
    if headers.get("upgrade", "").lower() != "websocket" or "sec-websocket-key" not in headers:
        # A plain HTTP probe (the tunnel's health check, a curious browser): answer and close.
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 27\r\nConnection: close\r\n\r\nxcoin stratum websocket ok\n")
        await writer.drain()
        return False
    origin = headers.get("origin", "")
    if origins and origin not in origins:
        log.warning("refused origin %r", origin)
        writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        return False
    resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_key(headers['sec-websocket-key'])}\r\n\r\n"
    )
    writer.write(resp.encode())
    await writer.drain()
    return True


async def relay(reader, writer, pool_host, pool_port, origins):
    peer = writer.get_extra_info("peername")
    try:
        if not await handshake(reader, writer, origins):
            return
        try:
            pr, pw = await asyncio.wait_for(asyncio.open_connection(pool_host, pool_port, limit=MAX_LINE), timeout=10)
        except Exception as e:
            log.warning("%s: pool unreachable: %s", peer, e)
            writer.write(encode_frame(struct.pack("!H", 1011), 0x8))
            await writer.drain()
            return
        log.info("%s: connected", peer)

        async def ws_to_pool():
            while True:
                opcode, data = await read_frame(reader)
                if opcode == 0x8:                       # close
                    writer.write(encode_frame(data[:2], 0x8))
                    await writer.drain()
                    return
                if opcode == 0x9:                       # ping -> pong
                    writer.write(encode_frame(data, 0xA))
                    await writer.drain()
                    continue
                if opcode in (0x1, 0x2):
                    pw.write(data.rstrip(b"\r\n") + b"\n")
                    await pw.drain()

        async def pool_to_ws():
            while True:
                line = await pr.readuntil(b"\n")
                if len(line) > MAX_LINE:
                    raise ConnectionError("pool line too large")
                writer.write(encode_frame(line.rstrip(b"\r\n"), 0x1))
                await writer.drain()

        tasks = [asyncio.create_task(ws_to_pool()), asyncio.create_task(pool_to_ws())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for t in done:
            exc = t.exception()
            if exc and not isinstance(exc, (asyncio.IncompleteReadError, ConnectionError)):
                log.info("%s: %s", peer, exc)
        pw.close()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError) as e:
        log.info("%s: closed (%s)", peer, e.__class__.__name__)
    except Exception as e:
        log.warning("%s: %s", peer, e)
    finally:
        writer.close()
        log.info("%s: done", peer)


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", default=os.environ.get("XCOIN_WS_LISTEN", "127.0.0.1:3336"))
    ap.add_argument("--pool", default=os.environ.get("XCOIN_WS_POOL", "127.0.0.1:3335"))
    ap.add_argument("--origin", action="append", default=[], help="allowed Origin (repeatable); none = any")
    a = ap.parse_args()
    lh, lp = a.listen.rsplit(":", 1)
    ph, pp = a.pool.rsplit(":", 1)
    origins = set(a.origin) or set(filter(None, os.environ.get("XCOIN_WS_ORIGINS", "").split(",")))
    server = await asyncio.start_server(lambda r, w: relay(r, w, ph, int(pp), origins), lh, int(lp), limit=MAX_LINE)
    log.info("stratum websocket bridge on %s -> pool %s (origins: %s)", a.listen, a.pool, ", ".join(sorted(origins)) or "any")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(main())
