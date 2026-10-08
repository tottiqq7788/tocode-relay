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
    def test_pair_forward_and_isolation(self):
        asyncio.run(self._scenario())

    def test_file_forward_stays_out_of_the_route_file(self):
        asyncio.run(self._file_scenario())

    async def _scenario(self):
        with tempfile.TemporaryDirectory() as directory:
            data = str(pathlib.Path(directory) / "routes.json")
            bound = asyncio.Event()
            holder = {}

            async def boot():
                state = server.RelayState(data)
                holder["state"] = state
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
            try:
                _, device = await http(port, "POST", "/v1/devices", {"name": "MacBook"})
                token = device["device_token"]
                _, pairing = await http(
                    port,
                    "POST",
                    "/v1/pairings",
                    {"role_id": "role-1", "role_name": "alpha", "display_name": "Alpha"},
                    token,
                )
                code = pairing["code"]
                status, first = await http(
                    port,
                    "POST",
                    f"/v1/pairings/{code}/redeem",
                    {"android_id": "phone-a", "android_name": "Pixel"},
                )
                self.assertEqual(status, 200)
                status, _ = await http(
                    port,
                    "POST",
                    f"/v1/pairings/{code}/redeem",
                    {"android_id": "phone-b", "android_name": "Other"},
                )
                self.assertEqual(status, 409)

                mac = await open_ws(port, token)
                phone = await open_ws(port, first["link_token"])
                self.assertEqual((await mac.recv())["side"], "mac")
                self.assertEqual((await phone.recv())["side"], "android")
                await phone.send({
                    "op": "text",
                    "link_id": first["link_id"],
                    "message_id": "m1",
                    "text": "hello-body-9f3",
                })
                inbound = await mac.recv()
                self.assertEqual(inbound["op"], "inbound")
                self.assertEqual(inbound["text"], "hello-body-9f3")
                accepted = await phone.recv()
                self.assertEqual(accepted["op"], "accepted")
                await mac.send({
                    "op": "reply",
                    "link_id": first["link_id"],
                    "message_id": "r1",
                    "text": "pong-body",
                })
                reply = await phone.recv()
                self.assertEqual(reply["text"], "pong-body")
                self.assertEqual((await mac.recv())["op"], "accepted")

                _, second_code = await http(
                    port,
                    "POST",
                    "/v1/pairings",
                    {"role_id": "role-1", "role_name": "alpha", "display_name": "Alpha 2"},
                    token,
                )
                _, second = await http(
                    port,
                    "POST",
                    f"/v1/pairings/{second_code['code']}/redeem",
                    {"android_id": "phone-b", "android_name": "Other"},
                )
                other = await open_ws(port, second["link_token"])
                await other.recv()
                await other.send({
                    "op": "text",
                    "link_id": first["link_id"],
                    "message_id": "steal",
                    "text": "nope",
                })
                denied = await other.recv()
                self.assertEqual(denied["code"], "forbidden")

                phone.writer.close()
                await asyncio.sleep(0.05)
                await mac.send({
                    "op": "reply",
                    "link_id": first["link_id"],
                    "message_id": "r2",
                    "text": "late-body",
                })
                offline = await mac.recv()
                self.assertEqual(offline["code"], "android_offline")

                await http(port, "DELETE", f"/v1/links/{first['link_id']}", token=token)
                await other.send({
                    "op": "text",
                    "link_id": second["link_id"],
                    "message_id": "m2",
                    "text": "still-routed",
                })
                # Mac may first observe nothing for the deleted link; the live link still routes.
                routed = await mac.recv()
                self.assertEqual(routed["link_id"], second["link_id"])
                self.assertEqual(routed["text"], "still-routed")
                self.assertEqual((await other.recv())["op"], "accepted")
                mac.writer.close()
                await asyncio.sleep(0.05)
                await other.send({
                    "op": "text",
                    "link_id": second["link_id"],
                    "message_id": "m3",
                    "text": "mac-gone",
                })
                gone = await other.recv()
                if gone.get("op") == "accepted":
                    gone = await other.recv()
                self.assertEqual(gone["code"], "mac_offline")

                status, rejected = await http(
                    port,
                    "POST",
                    "/v1/pairings",
                    {"role_id": "role-1", "role_name": "alpha", "prompt": "system prompt"},
                    token,
                )
                self.assertEqual(status, 400)
                self.assertEqual(rejected["error"], "forbidden_field")

                raw = pathlib.Path(data).read_text(encoding="utf-8")
                self.assertNotIn("hello-body-9f3", raw)
                self.assertNotIn("pong-body", raw)
                self.assertNotIn("late-body", raw)
                self.assertNotIn("system prompt", raw)
                self.assertEqual(holder["state"].stored_messages, [])
                self.assertEqual(oct(os.stat(data).st_mode & 0o777), "0o600")
            finally:
                for sock in locals().get("mac"), locals().get("phone"), locals().get("other"):
                    if sock is not None:
                        sock.writer.close()
                holder["server"].close()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    async def _file_scenario(self):
        with tempfile.TemporaryDirectory() as directory:
            data = str(pathlib.Path(directory) / "routes.json")
            bound = asyncio.Event()
            holder = {}

            async def boot():
                state = server.RelayState(data)
                holder["state"] = state
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
            mac = phone = None
            try:
                _, device = await http(port, "POST", "/v1/devices", {"name": "MacBook"})
                token = device["device_token"]
                _, pairing = await http(
                    port,
                    "POST",
                    "/v1/pairings",
                    {"role_id": "role-1", "role_name": "alpha", "display_name": "Alpha"},
                    token,
                )
                _, link = await http(
                    port,
                    "POST",
                    f"/v1/pairings/{pairing['code']}/redeem",
                    {"android_id": "phone-a", "android_name": "Pixel"},
                )
                mac = await open_ws(port, token)
                phone = await open_ws(port, link["link_token"])
                await mac.recv()
                await phone.recv()
                body = b"FILEBYTES-MARKER"
                await phone.send({
                    "op": "file",
                    "link_id": link["link_id"],
                    "message_id": "f1",
                    "name": "note.txt",
                    "size": len(body),
                    "kind": "file",
                    "text": "请看附件",
                })
                await phone.send_bytes(body)
                header = await mac.recv()
                opcode, payload = await mac.recv_frame()
                self.assertEqual(header["op"], "inbound_file")
                self.assertEqual(header["name"], "note.txt")
                self.assertEqual(header["text"], "请看附件")
                self.assertEqual(opcode, 2)
                self.assertEqual(payload, body)
                self.assertEqual((await phone.recv())["op"], "accepted")
                await mac.send({
                    "op": "file_reply",
                    "link_id": link["link_id"],
                    "message_id": "back",
                    "name": "note.txt",
                    "size": len(body),
                    "kind": "file",
                })
                await mac.send_bytes(body)
                echoed = await phone.recv()
                echo_op, echo_body = await phone.recv_frame()
                self.assertEqual(echoed["op"], "file")
                self.assertEqual(echoed["name"], "note.txt")
                self.assertEqual(echo_op, 2)
                self.assertEqual(echo_body, body)
                self.assertEqual((await mac.recv())["op"], "accepted")

                await phone.send({
                    "op": "file",
                    "link_id": link["link_id"],
                    "message_id": "big",
                    "name": "big.bin",
                    "size": server.FILE_LIMIT + 1,
                    "kind": "file",
                })
                too_big = await phone.recv()
                self.assertEqual(too_big["code"], "empty")

                await http(port, "DELETE", f"/v1/links/{link['link_id']}", token=token)
                await phone.send({
                    "op": "file",
                    "link_id": link["link_id"],
                    "message_id": "gone",
                    "name": "late.txt",
                    "size": 4,
                    "kind": "file",
                })
                await phone.send_bytes(b"late")
                denied = await phone.recv()
                self.assertEqual(denied["code"], "unknown_link")

                raw = pathlib.Path(data).read_text(encoding="utf-8")
                self.assertNotIn("FILEBYTES-MARKER", raw)
                self.assertNotIn("请看附件", raw)
                self.assertEqual(holder["state"].stored_messages, [])
            finally:
                for sock in (mac, phone):
                    if sock is not None:
                        sock.writer.close()
                holder["server"].close()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass


if __name__ == "__main__":
    unittest.main()
