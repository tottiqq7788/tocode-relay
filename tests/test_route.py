import asyncio
import base64
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import server


def encode_client_frame(opcode: int, payload: bytes) -> bytes:
    mask = os.urandom(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    length = len(payload)
    if length < 126:
        header = bytes([0x80 | opcode, 0x80 | length])
    elif length < 65536:
        header = bytes([0x80 | opcode, 0x80 | 126]) + length.to_bytes(2, "big")
    else:
        header = bytes([0x80 | opcode, 0x80 | 127]) + length.to_bytes(8, "big")
    return header + mask + masked


def encode_client(text: str) -> bytes:
    return encode_client_frame(1, text.encode())


class Socket:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.stream = None

    async def recv_frame(self):
        return await server.read_frame(self.stream)

    async def recv(self):
        opcode, payload = await self.recv_frame()
        if opcode != 1:
            return await self.recv()
        return json.loads(payload.decode())

    async def send(self, payload: dict):
        self.writer.write(encode_client(json.dumps(payload)))
        await self.writer.drain()

    async def send_bytes(self, payload: bytes):
        self.writer.write(encode_client_frame(2, payload))
        await self.writer.drain()


async def open_ws(port: int, token: str) -> Socket:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    key = base64.b64encode(os.urandom(16)).decode()
    writer.write(
        (
            f"GET /v1/ws?token={token} HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
    )
    await writer.drain()
    opened = await server.read_http(reader)
    status = opened[0]
    if " 101 " not in status:
        raise AssertionError(status)
    accept = base64.b64encode(
        hashlib.sha1((key + server.WS_GUID).encode()).digest()
    ).decode()
    if opened[1].get("sec-websocket-accept") != accept:
        raise AssertionError("accept")
    sock = Socket(reader, writer)
    sock.stream = server.ByteStream(reader, opened[3])
    return sock


async def http(port: int, method: str, path: str, body: dict | None = None, token: str = ""):
    raw = b"" if body is None else json.dumps(body).encode()
    header = (
        f"{method} {path} HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(raw)}\r\n"
    )
    if token:
        header += f"Authorization: Bearer {token}\r\n"
    header += "Connection: close\r\n\r\n"
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(header.encode() + raw)
    await writer.drain()
    opened = await server.read_http(reader)
    status = int(opened[0].split(" ")[1])
    payload = json.loads(opened[2].decode() or "{}")
    writer.close()
    return status, payload



class RouteTests(unittest.TestCase):
    def test_command_isolation_and_revoke(self):
        asyncio.run(self._scenario())

    async def _scenario(self):
        with tempfile.TemporaryDirectory() as directory:
            data = str(pathlib.Path(directory) / "routes.json")
            bound = asyncio.Event()
            holder = {}

            async def boot():
                state = server.RelayState(data)
                tcp = await asyncio.start_server(
                    lambda reader, writer: server.handle(reader, writer, state),
                    "127.0.0.1",
                    0,
                )
                holder["server"] = tcp
                holder["port"] = tcp.sockets[0].getsockname()[1]
                bound.set()
                async with tcp:
                    await tcp.serve_forever()

            task = asyncio.create_task(boot())
            await asyncio.wait_for(bound.wait(), 3)
            port = holder["port"]
            clients = []
            try:
                _, mac_a = await http(port, "POST", "/v1/devices", {"name": "Mac A"})
                _, mac_b = await http(port, "POST", "/v1/devices", {"name": "Mac B"})
                _, pairing = await http(port, "POST", "/v1/pairings", {}, mac_a["device_token"])
                status, link = await http(
                    port, "POST", f"/v1/pairings/{pairing['code']}/redeem",
                    {"android_id": "phone", "android_name": "Pixel"},
                )
                self.assertEqual(status, 200)
                self.assertNotIn("role_id", link)
                status, again = await http(
                    port, "POST", f"/v1/pairings/{pairing['code']}/redeem",
                    {"android_id": "phone", "android_name": "Pixel"},
                )
                self.assertEqual(status, 409)

                _, pairing_b = await http(port, "POST", "/v1/pairings", {}, mac_b["device_token"])
                _, link_b = await http(
                    port, "POST", f"/v1/pairings/{pairing_b['code']}/redeem",
                    {"android_id": "phone", "android_name": "Pixel"},
                )

                mac = await open_ws(port, mac_a["device_token"])
                other = await open_ws(port, mac_b["device_token"])
                phone = await open_ws(port, link["link_token"])
                clients.extend([mac, other, phone])
                self.assertEqual((await mac.recv())["side"], "mac")
                self.assertEqual((await other.recv())["side"], "mac")
                self.assertEqual((await phone.recv())["side"], "android")

                await phone.send({"op": "command", "request_id": "r1", "action": "status"})
                inbound = await mac.recv()
                self.assertEqual(inbound["op"], "command_inbound")
                self.assertEqual(inbound["action"], "status")
                self.assertEqual((await phone.recv())["op"], "accepted")
                await mac.send({
                    "op": "result", "link_id": link["link_id"], "request_id": "r1",
                    "ok": True, "text": "secret-result-body",
                })
                result = await phone.recv()
                self.assertEqual(result["text"], "secret-result-body")
                self.assertTrue(result["ok"])

                await phone.send({"op": "command", "request_id": "r2", "action": "shell"})
                denied = await phone.recv()
                self.assertEqual(denied["code"], "bad_action")

                phone_b = await open_ws(port, link_b["link_token"])
                clients.append(phone_b)
                self.assertEqual((await phone_b.recv())["side"], "android")
                await phone_b.send({"op": "command", "request_id": "b1", "action": "status"})
                other_in = await other.recv()
                self.assertEqual(other_in["link_id"], link_b["link_id"])

                status, _ = await http(port, "DELETE", f"/v1/links/{link['link_id']}", token=link["link_token"])
                self.assertEqual(status, 200)
                revoked = await mac.recv()
                self.assertEqual(revoked["op"], "link_revoked")
                status, missing = await http(
                    port, "POST", "/v1/pairings", {}, link["link_token"]
                )
                self.assertEqual(missing.get("error"), "unauthorized")
                saved = pathlib.Path(data).read_text(encoding="utf-8")
                self.assertNotIn("secret-result-body", saved)
                self.assertNotIn("status", saved)
            finally:
                for client in clients:
                    client.writer.close()
                holder["server"].close()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass


class AppChannelTests(unittest.TestCase):
    def test_app_channel_is_separate_and_not_stored(self):
        asyncio.run(self._scenario())

    async def _scenario(self):
        with tempfile.TemporaryDirectory() as directory:
            data = str(pathlib.Path(directory) / "routes.json")
            bound = asyncio.Event()
            holder = {}

            async def boot():
                state = server.RelayState(data)
                tcp = await asyncio.start_server(
                    lambda reader, writer: server.handle(reader, writer, state),
                    "127.0.0.1",
                    0,
                )
                holder["server"] = tcp
                holder["port"] = tcp.sockets[0].getsockname()[1]
                bound.set()
                async with tcp:
                    await tcp.serve_forever()

            task = asyncio.create_task(boot())
            await asyncio.wait_for(bound.wait(), 3)
            port = holder["port"]
            clients = []
            try:
                _, mac = await http(port, "POST", "/v1/devices", {"name": "Mac"})
                _, pairing = await http(port, "POST", "/v1/pairings", {}, mac["device_token"])
                _, link = await http(
                    port, "POST", f"/v1/pairings/{pairing['code']}/redeem",
                    {"android_id": "phone", "android_name": "Pixel"},
                )
                mac_ws = await open_ws(port, mac["device_token"])
                phone = await open_ws(port, link["link_token"])
                clients.extend([mac_ws, phone])
                self.assertEqual((await mac_ws.recv())["side"], "mac")
                self.assertEqual((await phone.recv())["side"], "android")

                await phone.send({
                    "op": "app", "request_id": "c1", "kind": "chat", "text": "CHAT_SECRET_BODY",
                    "path": "/tmp/nope",
                })
                denied = await phone.recv()
                self.assertEqual(denied["code"], "bad_action")

                await phone.send({"op": "app", "request_id": "c2", "kind": "chat", "text": "CHAT_SECRET_BODY"})
                inbound = await mac_ws.recv()
                self.assertEqual(inbound["op"], "app_inbound")
                self.assertNotIn("path", inbound)
                self.assertEqual((await phone.recv())["op"], "accepted")
                await mac_ws.send({
                    "op": "app_result",
                    "link_id": link["link_id"],
                    "request_id": "c2",
                    "kind": "chat",
                    "ok": True,
                    "text": "REPLY_SECRET_BODY",
                    "body": {"entries": [{"name": "DIR_SECRET_NAME", "path": "src", "kind": "directory"}]},
                })
                result = await phone.recv()
                self.assertEqual(result["op"], "app_result")
                self.assertEqual(result["text"], "REPLY_SECRET_BODY")
                saved = pathlib.Path(data).read_text(encoding="utf-8")
                self.assertNotIn("CHAT_SECRET_BODY", saved)
                self.assertNotIn("REPLY_SECRET_BODY", saved)
                self.assertNotIn("DIR_SECRET_NAME", saved)

                await phone.send({"op": "command", "request_id": "s1", "action": "shell"})
                self.assertEqual((await phone.recv())["code"], "bad_action")
            finally:
                for client in clients:
                    client.writer.close()
                holder["server"].close()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass


if __name__ == "__main__":
    unittest.main()
