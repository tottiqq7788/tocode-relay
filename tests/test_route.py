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

BINDING_KEY = "mac-binding-secret"
BINDING_DIGEST = hashlib.sha256(BINDING_KEY.encode()).hexdigest()


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


async def open_ws(port: int, token: str, *, via_query: bool = False) -> Socket:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    key = base64.b64encode(os.urandom(16)).decode()
    path = f"/v1/ws?token={token}" if via_query else "/v1/ws"
    writer.write(
        (
            f"GET {path} HTTP/1.1\r\n"
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
    if not via_query:
        await sock.send({"op": "auth", "token": token})
    return sock


async def http(port: int, method: str, path: str, body: dict | None = None, token: str = "", extra_headers: dict | None = None):
    status, payload, _headers = await http_full(port, method, path, body, token, extra_headers)
    return status, payload


async def http_full(port: int, method: str, path: str, body: dict | None = None, token: str = "", extra_headers: dict | None = None):
    raw = b"" if body is None else json.dumps(body).encode()
    header = (
        f"{method} {path} HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(raw)}\r\n"
    )
    if token:
        header += f"Authorization: Bearer {token}\r\n"
    if extra_headers:
        for key, value in extra_headers.items():
            header += f"{key}: {value}\r\n"
    header += "Connection: close\r\n\r\n"
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(header.encode() + raw)
    await writer.drain()
    opened = await server.read_http(reader)
    status = int(opened[0].split(" ")[1])
    payload = json.loads(opened[2].decode() or "{}") if opened[2] else {}
    writer.close()
    return status, payload, opened[1]



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
                _, pairing = await http(
                    port, "POST", "/v1/pairings",
                    {"binding_key_digest": BINDING_DIGEST}, mac_a["device_token"],
                )
                status, link = await http(
                    port, "POST", f"/v1/pairings/{pairing['code']}/redeem",
                    {"android_id": "phone", "android_name": "Pixel", "binding_key": BINDING_KEY},
                )
                self.assertEqual(status, 200)
                self.assertNotIn("role_id", link)
                status, again = await http(
                    port, "POST", f"/v1/pairings/{pairing['code']}/redeem",
                    {"android_id": "phone", "android_name": "Pixel", "binding_key": BINDING_KEY},
                )
                self.assertEqual(status, 409)

                _, pairing_b = await http(
                    port, "POST", "/v1/pairings",
                    {"binding_key_digest": BINDING_DIGEST}, mac_b["device_token"],
                )
                _, link_b = await http(
                    port, "POST", f"/v1/pairings/{pairing_b['code']}/redeem",
                    {"android_id": "phone", "android_name": "Pixel", "binding_key": BINDING_KEY},
                )

                mac = await open_ws(port, mac_a["device_token"])
                other = await open_ws(port, mac_b["device_token"])
                phone = await open_ws(port, link["link_token"])
                clients.extend([mac, other, phone])
                self.assertEqual((await mac.recv())["side"], "mac")
                self.assertEqual((await other.recv())["side"], "mac")
                self.assertEqual((await phone.recv())["side"], "android")

                await phone.send({"op": "command", "request_id": "r1", "action": "remote-buttons"})
                inbound = await mac.recv()
                self.assertEqual(inbound["op"], "command_inbound")
                self.assertEqual(inbound["action"], "remote-buttons")
                self.assertNotIn("target", inbound)
                self.assertEqual((await phone.recv())["op"], "accepted")
                await mac.send({
                    "op": "result", "link_id": link["link_id"], "request_id": "r1",
                    "ok": True, "text": "secret-result-body",
                })
                result = await phone.recv()
                self.assertEqual(result["text"], "secret-result-body")
                self.assertTrue(result["ok"])

                await phone.send({"op": "command", "request_id": "w1", "action": "wheel-vertical"})
                self.assertEqual((await phone.recv())["code"], "bad_action")
                await phone.send({"op": "command", "request_id": "st1", "action": "status"})
                self.assertEqual((await phone.recv())["code"], "bad_action")
                await phone.send({
                    "op": "command", "request_id": "bd1", "action": "blackout",
                    "target": {"display_id": "d1", "space_id": 7},
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")
                await phone.send({"op": "command", "request_id": "bd2", "action": "blackout-dismiss"})
                self.assertEqual((await phone.recv())["code"], "bad_action")
                await phone.send({
                    "op": "command", "request_id": "lk1", "action": "lock",
                    "target": {"display_id": "d1", "space_id": 7},
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")
                await phone.send({
                    "op": "command", "request_id": "rp0", "action": "remote-press",
                    "target": {"button_id": "abc", "shortcut": "secret"},
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")
                await phone.send({
                    "op": "command", "request_id": "rp1", "action": "remote-press",
                    "target": {"button_id": "6f1c1c1c-1c1c-4c1c-8c1c-1c1c1c1c1c1c"},
                })
                inbound = await mac.recv()
                self.assertEqual(inbound["action"], "remote-press")
                self.assertEqual(inbound["target"], {"button_id": "6f1c1c1c-1c1c-4c1c-8c1c-1c1c1c1c1c1c"})
                self.assertEqual((await phone.recv())["op"], "accepted")
                await phone.send({"op": "command", "request_id": "ds0", "action": "desktop-switch"})
                self.assertEqual((await phone.recv())["code"], "bad_action")
                await phone.send({
                    "op": "command", "request_id": "ds1", "action": "desktop-switch",
                    "target": {"display_id": "d1", "space_id": 7, "window_id": 11, "pid": 4},
                })
                inbound = await mac.recv()
                self.assertEqual(inbound["action"], "desktop-switch")
                self.assertEqual(inbound["target"]["display_id"], "d1")
                self.assertEqual(inbound["target"]["window_id"], 11)
                self.assertEqual((await phone.recv())["op"], "accepted")
                await mac.send({
                    "op": "result", "link_id": link["link_id"], "request_id": "ds1",
                    "ok": True, "text": "已切换",
                    "body": {"displays": [{"title": "桌面窗口标题不会落盘", "spaces": []}]},
                })
                listed = await phone.recv()
                self.assertEqual(listed["body"]["displays"][0]["title"], "桌面窗口标题不会落盘")

                await phone.send({"op": "command", "request_id": "r2", "action": "shell"})
                denied = await phone.recv()
                self.assertEqual(denied["code"], "bad_action")

                phone_b = await open_ws(port, link_b["link_token"])
                clients.append(phone_b)
                self.assertEqual((await phone_b.recv())["side"], "android")
                await phone_b.send({"op": "command", "request_id": "b1", "action": "desktops"})
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
                self.assertNotIn("桌面窗口标题不会落盘", saved)
                self.assertNotIn("6f1c1c1c-1c1c-4c1c-8c1c-1c1c1c1c1c1c", saved)
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
                _, pairing = await http(
                    port, "POST", "/v1/pairings",
                    {"binding_key_digest": BINDING_DIGEST}, mac["device_token"],
                )
                _, link = await http(
                    port, "POST", f"/v1/pairings/{pairing['code']}/redeem",
                    {"android_id": "phone", "android_name": "Pixel", "binding_key": BINDING_KEY},
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

                await phone.send({
                    "op": "app", "request_id": "c3", "kind": "projects",
                    "profile": "../x", "project_id": "p_abc12345",
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")

                await phone.send({
                    "op": "app", "request_id": "c4", "kind": "projects",
                    "profile": "liubei", "project_id": "p_abc12345",
                })
                routed = await mac_ws.recv()
                self.assertEqual(routed["profile"], "liubei")
                self.assertEqual(routed["project_id"], "p_abc12345")
                self.assertEqual((await phone.recv())["op"], "accepted")
                saved = pathlib.Path(data).read_text(encoding="utf-8")
                self.assertNotIn("liubei", saved)
                self.assertNotIn("p_abc12345", saved)

                await phone.send({
                    "op": "app", "request_id": "m1", "kind": "models",
                    "profile": "liubei",
                })
                routed = await mac_ws.recv()
                self.assertEqual(routed["kind"], "models")
                self.assertEqual(routed["profile"], "liubei")
                self.assertEqual((await phone.recv())["op"], "accepted")

                await phone.send({
                    "op": "app", "request_id": "m2", "kind": "model_select",
                    "profile": "liubei", "title": "deepseek", "text": "deepseek-flash",
                })
                routed = await mac_ws.recv()
                self.assertEqual(routed["kind"], "model_select")
                self.assertEqual(routed["title"], "deepseek")
                self.assertEqual(routed["text"], "deepseek-flash")
                self.assertEqual((await phone.recv())["op"], "accepted")

                await phone.send({
                    "op": "app", "request_id": "m3", "kind": "model_select",
                    "profile": "liubei", "title": "Bad Provider", "text": "deepseek-flash",
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")

                await phone.send({
                    "op": "app", "request_id": "m4", "kind": "models",
                    "profile": "liubei", "text": "extra",
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")

                for index, bad in enumerate(["/etc", "code/../..", "./code", "code//app", "code/\x00", "a" * 1025]):
                    await phone.send({"op": "app", "request_id": f"f{index}", "kind": "folders", "path": bad})
                    self.assertEqual((await phone.recv())["code"], "bad_action")

                await phone.send({"op": "app", "request_id": "f8", "kind": "chat", "session_id": "api_x", "text": "hi", "path": "code"})
                self.assertEqual((await phone.recv())["code"], "bad_action")

                await phone.send({"op": "app", "request_id": "f9", "kind": "folders", "path": "code/PATH_SECRET_NAME"})
                routed = await mac_ws.recv()
                self.assertEqual(routed["kind"], "folders")
                self.assertEqual(routed["path"], "code/PATH_SECRET_NAME")
                self.assertEqual((await phone.recv())["op"], "accepted")
                self.assertNotIn("PATH_SECRET_NAME", pathlib.Path(data).read_text(encoding="utf-8"))

                await phone.send({
                    "op": "app", "request_id": "d1", "kind": "session_delete",
                    "session_id": "api_x", "profile": "liubei", "project_id": "p_abc12345",
                })
                routed = await mac_ws.recv()
                self.assertEqual(routed["kind"], "session_delete")
                self.assertEqual(routed["session_id"], "api_x")
                self.assertEqual((await phone.recv())["op"], "accepted")

                await phone.send({
                    "op": "app", "request_id": "n1", "kind": "session_rename",
                    "session_id": "api_x", "title": "TITLE_SECRET_NAME",
                })
                routed = await mac_ws.recv()
                self.assertEqual(routed["kind"], "session_rename")
                self.assertEqual(routed["title"], "TITLE_SECRET_NAME")
                self.assertEqual((await phone.recv())["op"], "accepted")
                self.assertNotIn("TITLE_SECRET_NAME", pathlib.Path(data).read_text(encoding="utf-8"))

                await phone.send({
                    "op": "app", "request_id": "p1", "kind": "preview",
                    "profile": "liubei", "project_id": "p_abc12345", "path": "src/PREVIEW_SECRET.md",
                })
                routed = await mac_ws.recv()
                self.assertEqual(routed["kind"], "preview")
                self.assertEqual(routed["path"], "src/PREVIEW_SECRET.md")
                self.assertEqual(routed["offset"], 0)
                self.assertEqual((await phone.recv())["op"], "accepted")

                await phone.send({
                    "op": "app", "request_id": "p2", "kind": "preview",
                    "profile": "liubei", "project_id": "p_abc12345", "path": "src/PREVIEW_SECRET.md",
                    "offset": 12000,
                })
                routed = await mac_ws.recv()
                self.assertEqual(routed["offset"], 12000)
                self.assertEqual((await phone.recv())["op"], "accepted")
                await phone.send({
                    "op": "app", "request_id": "p3", "kind": "preview",
                    "path": "src/a.md", "offset": -1,
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")
                self.assertNotIn("PREVIEW_SECRET", pathlib.Path(data).read_text(encoding="utf-8"))

                await phone.send({
                    "op": "app", "request_id": "t1", "kind": "tree",
                    "profile": "liubei", "project_id": "p_abc12345",
                    "path": "chapters", "offset": 80,
                })
                routed = await mac_ws.recv()
                self.assertEqual(routed["kind"], "tree")
                self.assertEqual(routed["path"], "chapters")
                self.assertEqual(routed["offset"], 80)
                self.assertEqual((await phone.recv())["op"], "accepted")
                await phone.send({
                    "op": "app", "request_id": "dl1", "kind": "download",
                    "profile": "liubei", "project_id": "p_abc12345",
                    "text": '["src/a.md","chapters"]',
                })
                routed = await mac_ws.recv()
                self.assertEqual(routed["kind"], "download")
                self.assertEqual(routed["text"], '["src/a.md","chapters"]')
                self.assertEqual((await phone.recv())["op"], "accepted")
                await phone.send({
                    "op": "app", "request_id": "t2", "kind": "tree",
                    "path": "chapters", "offset": -1,
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")
                await phone.send({
                    "op": "app", "request_id": "t3", "kind": "tree",
                    "path": "../chapters",
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")
                self.assertNotIn("chapters", pathlib.Path(data).read_text(encoding="utf-8"))

                await phone.send({
                    "op": "app", "request_id": "m1", "kind": "messages",
                    "session_id": "api_x", "cursor": "tail:0",
                })
                routed = await mac_ws.recv()
                self.assertEqual(routed["kind"], "messages")
                self.assertEqual(routed["cursor"], "tail:0")
                self.assertEqual((await phone.recv())["op"], "accepted")
                await phone.send({
                    "op": "app", "request_id": "m2", "kind": "messages",
                    "session_id": "api_x", "cursor": "older:15",
                })
                routed = await mac_ws.recv()
                self.assertEqual(routed["cursor"], "older:15")
                self.assertEqual((await phone.recv())["op"], "accepted")
                await phone.send({
                    "op": "app", "request_id": "m3", "kind": "chat",
                    "text": "hi", "cursor": "tail:1",
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")
                await phone.send({
                    "op": "app", "request_id": "m4", "kind": "messages",
                    "session_id": "api_x", "cursor": "older:0",
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")
                self.assertNotIn("tail:0", pathlib.Path(data).read_text(encoding="utf-8"))
                self.assertNotIn("older:15", pathlib.Path(data).read_text(encoding="utf-8"))

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


    def test_project_file_stays_in_memory(self):
        asyncio.run(self._project_file())

    async def _project_file(self):
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
                _, pairing = await http(
                    port, "POST", "/v1/pairings",
                    {"binding_key_digest": BINDING_DIGEST}, mac_a["device_token"],
                )
                _, link = await http(
                    port, "POST", f"/v1/pairings/{pairing['code']}/redeem",
                    {"android_id": "phone", "android_name": "Pixel", "binding_key": BINDING_KEY},
                )
                mac = await open_ws(port, mac_a["device_token"])
                phone = await open_ws(port, link["link_token"])
                clients.extend([mac, phone])
                self.assertEqual((await mac.recv())["side"], "mac")
                self.assertEqual((await phone.recv())["side"], "android")

                await phone.send_bytes(b"NOPE")
                self.assertEqual((await phone.recv())["message"], "不接受二进制")
                await phone.send({
                    "op": "project_file", "request_id": "bad-path", "name": "a.jpg", "size": 4,
                    "kind": "image", "profile": "default", "project_id": "p_demo1",
                    "path": "对话附件-图片/a.jpg",
                })
                refused = await phone.recv()
                self.assertEqual(refused["code"], "bad_action")
                self.assertEqual(refused["message"], "不能指定保存位置")
                await phone.send({
                    "op": "project_file", "request_id": "bad-name", "name": "../a.jpg", "size": 4,
                    "kind": "file", "profile": "default", "project_id": "p_demo1",
                })
                self.assertEqual((await phone.recv())["code"], "bad_action")
                with self.assertRaises(asyncio.TimeoutError):
                    await asyncio.wait_for(mac.recv(), 0.3)

                await phone.send({
                    "op": "project_file", "request_id": "f1", "name": "attach-marker.jpg", "size": 11,
                    "kind": "image", "profile": "default", "project_id": "p_demo1",
                })
                await phone.send_bytes(b"ATTACHBYTES")
                header = await mac.recv()
                self.assertEqual(header["op"], "project_file_inbound")
                self.assertEqual(header["name"], "attach-marker.jpg")
                self.assertEqual(header["kind"], "image")
                self.assertEqual(header["project_id"], "p_demo1")
                self.assertNotIn("path", header)
                opcode, payload = await mac.recv_frame()
                self.assertEqual(opcode, 2)
                self.assertEqual(payload, b"ATTACHBYTES")
                self.assertEqual((await phone.recv())["op"], "accepted")
                await mac.send({
                    "op": "project_file_result", "link_id": link["link_id"], "request_id": "f1",
                    "ok": True, "path": "对话附件-图片/attach-marker.jpg",
                })
                saved_path = await phone.recv()
                self.assertTrue(saved_path["ok"])
                self.assertEqual(saved_path["path"], "对话附件-图片/attach-marker.jpg")
                await mac.send({
                    "op": "project_file_result", "link_id": link["link_id"], "request_id": "f2",
                    "ok": True, "path": "/tmp/secret",
                })
                denied = await phone.recv()
                self.assertFalse(denied["ok"])
                self.assertNotIn("path", denied)
                await phone.send({
                    "op": "project_file", "request_id": "h1", "name": "staged.jpg", "size": 4,
                    "kind": "image", "profile": "default", "project_id": "p_demo1", "hold": True,
                })
                await phone.send_bytes(b"HOLD")
                held_header = await mac.recv()
                self.assertEqual(held_header["op"], "project_file_inbound")
                self.assertIs(held_header["hold"], True)
                self.assertNotIn("path", held_header)
                opcode, payload = await mac.recv_frame()
                self.assertEqual(opcode, 2)
                self.assertEqual(payload, b"HOLD")
                self.assertEqual((await phone.recv())["op"], "accepted")
                await mac.send({
                    "op": "project_file_result", "link_id": link["link_id"], "request_id": "h1",
                    "ok": True, "hold_id": "11111111-1111-1111-1111-111111111111",
                })
                held = await phone.recv()
                self.assertTrue(held["ok"])
                self.assertEqual(held["hold_id"], "11111111-1111-1111-1111-111111111111")
                self.assertNotIn("path", held)
                await mac.send({
                    "op": "project_file_result", "link_id": link["link_id"], "request_id": "both",
                    "ok": True, "hold_id": "11111111-1111-1111-1111-111111111111",
                    "path": "对话附件-图片/staged.jpg",
                })
                both = await phone.recv()
                self.assertTrue(both["ok"])
                self.assertEqual(both["hold_id"], "11111111-1111-1111-1111-111111111111")
                self.assertEqual(both["path"], "对话附件-图片/staged.jpg")
                await mac.send({
                    "op": "project_file_result", "link_id": link["link_id"], "request_id": "bad-both",
                    "ok": True, "hold_id": "11111111-1111-1111-1111-111111111111",
                    "path": "/etc/passwd",
                })
                self.assertFalse((await phone.recv())["ok"])
                await mac.send({
                    "op": "project_file_result", "link_id": link["link_id"], "request_id": "bad-hold",
                    "ok": True, "hold_id": "../outside",
                })
                self.assertFalse((await phone.recv())["ok"])
                await phone.send({
                    "op": "project_file_place", "request_id": "p1",
                    "hold_id": "11111111-1111-1111-1111-111111111111",
                    "profile": "default", "project_id": "p_demo1", "path": "对话附件-图片/x.jpg",
                })
                self.assertEqual((await phone.recv())["message"], "不能指定保存位置")
                await phone.send({
                    "op": "project_file_place", "request_id": "p1",
                    "hold_id": "11111111-1111-1111-1111-111111111111",
                    "profile": "default", "project_id": "p_demo1",
                })
                placed = await mac.recv()
                self.assertEqual(placed["op"], "project_file_place")
                self.assertEqual(placed["hold_id"], "11111111-1111-1111-1111-111111111111")
                self.assertNotIn("path", placed)
                self.assertNotIn("name", placed)
                await mac.send({
                    "op": "project_file_result", "link_id": link["link_id"], "request_id": "p1",
                    "ok": True, "path": "对话附件-图片/staged.jpg",
                })
                final = await phone.recv()
                self.assertEqual(final["path"], "对话附件-图片/staged.jpg")
                await phone.send({
                    "op": "project_file_drop", "request_id": "d1",
                    "hold_id": "11111111-1111-1111-1111-111111111111",
                })
                dropped_in = await mac.recv()
                self.assertEqual(dropped_in["op"], "project_file_drop")
                self.assertNotIn("path", dropped_in)
                await mac.send({
                    "op": "project_file_result", "link_id": link["link_id"], "request_id": "d1",
                    "ok": True, "dropped": True,
                })
                gone = await phone.recv()
                self.assertTrue(gone["dropped"])
                self.assertNotIn("path", gone)
                stored = pathlib.Path(data).read_text(encoding="utf-8")
                self.assertNotIn("ATTACHBYTES", stored)
                self.assertNotIn("HOLD", stored)
                self.assertNotIn("attach-marker.jpg", stored)
                self.assertNotIn("staged.jpg", stored)
                self.assertNotIn("11111111-1111-1111-1111-111111111111", stored)
                self.assertNotIn("对话附件", stored)
            finally:
                for client in clients:
                    client.writer.close()
                holder["server"].close()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass


class BrowserCorsTests(unittest.IsolatedAsyncioTestCase):
    async def test_redeem_and_unlink_expose_cors(self):
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
            try:
                _, mac = await http(port, "POST", "/v1/devices", {"name": "Mac"})
                _, pairing = await http(
                    port, "POST", "/v1/pairings",
                    {"binding_key_digest": BINDING_DIGEST}, mac["device_token"],
                )
                code = pairing["code"]
                status, _body, preflight = await http_full(
                    port, "OPTIONS", f"/v1/pairings/{code}/redeem",
                    extra_headers={"Origin": "http://localhost:5173"},
                )
                self.assertEqual(status, 204)
                self.assertEqual(preflight.get("access-control-allow-origin"), "*")
                self.assertIn("POST", preflight.get("access-control-allow-methods", ""))

                status, link, redeem_headers = await http_full(
                    port, "POST", f"/v1/pairings/{code}/redeem",
                    {"android_id": "web-1", "android_name": "Chrome", "binding_key": BINDING_KEY},
                    extra_headers={"Origin": "http://localhost:5173"},
                )
                self.assertEqual(status, 200)
                self.assertEqual(redeem_headers.get("access-control-allow-origin"), "*")
                self.assertIn("link_token", link)

                status, _ok, delete_headers = await http_full(
                    port, "DELETE", f"/v1/links/{link['link_id']}",
                    token=link["link_token"],
                    extra_headers={"Origin": "http://localhost:5173"},
                )
                self.assertEqual(status, 200)
                self.assertEqual(delete_headers.get("access-control-allow-origin"), "*")

                status, _health, health_headers = await http_full(port, "GET", "/health")
                self.assertEqual(status, 200)
                self.assertNotIn("access-control-allow-origin", health_headers)
            finally:
                holder["server"].close()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass


class BindingKeyTests(unittest.IsolatedAsyncioTestCase):
    async def test_pairing_requires_digest_and_redeem_checks_key(self):
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
                holder["state"] = state
                bound.set()
                async with tcp:
                    await tcp.serve_forever()

            task = asyncio.create_task(boot())
            await asyncio.wait_for(bound.wait(), 3)
            port = holder["port"]
            try:
                _, mac = await http(port, "POST", "/v1/devices", {"name": "Mac"})
                status, missing = await http(port, "POST", "/v1/pairings", {}, mac["device_token"])
                self.assertEqual(status, 400)
                self.assertEqual(missing.get("error"), "missing_binding_key_digest")

                status, forbidden = await http(
                    port, "POST", "/v1/pairings",
                    {"binding_key_digest": BINDING_DIGEST, "binding_key": BINDING_KEY},
                    mac["device_token"],
                )
                self.assertEqual(status, 400)
                self.assertEqual(forbidden.get("error"), "forbidden_field")

                _, pairing = await http(
                    port, "POST", "/v1/pairings",
                    {"binding_key_digest": BINDING_DIGEST}, mac["device_token"],
                )
                status, wrong = await http(
                    port, "POST", f"/v1/pairings/{pairing['code']}/redeem",
                    {"android_id": "phone", "binding_key": "wrong-key"},
                )
                self.assertEqual(status, 401)
                self.assertEqual(wrong.get("error"), "unauthorized")
                self.assertEqual(holder["state"].links, {})

                status, missing_key = await http(
                    port, "POST", f"/v1/pairings/{pairing['code']}/redeem",
                    {"android_id": "phone"},
                )
                self.assertEqual(status, 401)

                status, link = await http(
                    port, "POST", f"/v1/pairings/{pairing['code']}/redeem",
                    {"android_id": "phone", "android_name": "Pixel", "binding_key": BINDING_KEY},
                )
                self.assertEqual(status, 200)
                self.assertIn("link_token", link)
                saved = pathlib.Path(data).read_text(encoding="utf-8")
                self.assertNotIn(BINDING_KEY, saved)
                self.assertNotIn(BINDING_DIGEST, saved)
                self.assertNotIn("binding_key", saved)
            finally:
                holder["server"].close()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass


class DiagTests(unittest.TestCase):
    def test_sanitize_blocks_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            server.configure_diag(directory)
            server.diag(
                "app.forward",
                link_id="link-1",
                device_id="mac-1",
                request_id="r1",
                kind="chat",
                token="secret-token",
                binding_key="mac-key",
                text="hello body",
                path="/Users/me/secret.txt",
                ok=True,
            )
            day = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y%m%d")
            path = pathlib.Path(directory) / f"relay-{day}.jsonl"
            self.assertTrue(path.is_file())
            row = json.loads(path.read_text(encoding="utf-8").strip().splitlines()[-1])
            self.assertEqual(row["event"], "app.forward")
            self.assertEqual(row["link_id"], "link-1")
            self.assertEqual(row["device_id"], "mac-1")
            self.assertEqual(row["request_id"], "r1")
            detail = row.get("detail") or {}
            self.assertEqual(detail.get("kind"), "chat")
            self.assertTrue(detail.get("ok"))
            blob = path.read_text(encoding="utf-8")
            self.assertNotIn("secret-token", blob)
            self.assertNotIn("mac-key", blob)
            self.assertNotIn("hello body", blob)
            self.assertNotIn("/Users/me", blob)
            self.assertNotIn("token", blob)
            self.assertNotIn("binding_key", blob)
            self.assertNotIn("\"text\"", blob)
            self.assertNotIn("\"path\"", blob)

    def test_ws_close_is_logged(self):
        asyncio.run(self._ws_close())

    async def _ws_close(self):
        with tempfile.TemporaryDirectory() as directory:
            data = str(pathlib.Path(directory) / "routes.json")
            diag_dir = pathlib.Path(directory) / "diagnostics"
            server.configure_diag(str(diag_dir))
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
            try:
                _, mac = await http(port, "POST", "/v1/devices", {"name": "Mac"})
                sock = await open_ws(port, mac["device_token"])
                ready = await sock.recv()
                self.assertEqual(ready["side"], "mac")
                sock.writer.close()
                await asyncio.sleep(0.3)
                day = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y%m%d")
                log = diag_dir / f"relay-{day}.jsonl"
                self.assertTrue(log.is_file())
                lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
                events = [row["event"] for row in lines]
                self.assertIn("ws.accept", events)
                self.assertIn("ws.close", events)
                close = next(row for row in lines if row["event"] == "ws.close")
                self.assertEqual(close["device_id"], mac["device_id"])
                self.assertIn(close.get("detail", {}).get("reason"), {"eof", "ws_close", "connection_error", "incomplete_read"})
                blob = log.read_text(encoding="utf-8")
                self.assertNotIn(mac["device_token"], blob)
            finally:
                holder["server"].close()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass


class WsAuthTests(unittest.IsolatedAsyncioTestCase):
    async def _boot(self):
        directory = tempfile.TemporaryDirectory()
        data = str(pathlib.Path(directory.name) / "routes.json")
        bound = asyncio.Event()
        holder = {"tmpdir": directory}

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
        holder["task"] = task
        return holder

    async def _stop(self, holder):
        holder["server"].close()
        holder["task"].cancel()
        try:
            await holder["task"]
        except asyncio.CancelledError:
            pass
        holder["tmpdir"].cleanup()

    async def test_first_frame_auth_ready(self):
        holder = await self._boot()
        try:
            port = holder["port"]
            _, mac = await http(port, "POST", "/v1/devices", {"name": "Mac"})
            sock = await open_ws(port, mac["device_token"])
            ready = await sock.recv()
            self.assertEqual(ready["op"], "ready")
            self.assertEqual(ready["side"], "mac")
            sock.writer.close()
        finally:
            await self._stop(holder)

    async def test_query_token_still_accepted_during_transition(self):
        holder = await self._boot()
        previous = server.WS_ALLOW_QUERY_TOKEN
        server.WS_ALLOW_QUERY_TOKEN = True
        try:
            port = holder["port"]
            _, mac = await http(port, "POST", "/v1/devices", {"name": "Mac"})
            sock = await open_ws(port, mac["device_token"], via_query=True)
            ready = await sock.recv()
            self.assertEqual(ready["side"], "mac")
            sock.writer.close()
        finally:
            server.WS_ALLOW_QUERY_TOKEN = previous
            await self._stop(holder)

    async def test_query_token_rejected_after_cutover(self):
        holder = await self._boot()
        previous = server.WS_ALLOW_QUERY_TOKEN
        server.WS_ALLOW_QUERY_TOKEN = False
        try:
            port = holder["port"]
            _, mac = await http(port, "POST", "/v1/devices", {"name": "Mac"})
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            key = base64.b64encode(os.urandom(16)).decode()
            writer.write(
                (
                    f"GET /v1/ws?token={mac['device_token']} HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode()
            )
            await writer.drain()
            opened = await server.read_http(reader)
            status = int(opened[0].split(" ")[1])
            self.assertEqual(status, 401)
            writer.close()
        finally:
            server.WS_ALLOW_QUERY_TOKEN = previous
            await self._stop(holder)

    async def test_bad_auth_frame_closes(self):
        holder = await self._boot()
        try:
            port = holder["port"]
            _, mac = await http(port, "POST", "/v1/devices", {"name": "Mac"})
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            key = base64.b64encode(os.urandom(16)).decode()
            writer.write(
                (
                    "GET /v1/ws HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode()
            )
            await writer.drain()
            opened = await server.read_http(reader)
            self.assertIn(" 101 ", opened[0])
            sock = Socket(reader, writer)
            sock.stream = server.ByteStream(reader, opened[3])
            await sock.send({"op": "auth", "token": "not-a-real-token"})
            with self.assertRaises((EOFError, ConnectionError, OSError, asyncio.IncompleteReadError)):
                await asyncio.wait_for(sock.recv_frame(), 2)
        finally:
            await self._stop(holder)

    async def test_non_auth_first_frame_closes(self):
        holder = await self._boot()
        try:
            port = holder["port"]
            await http(port, "POST", "/v1/devices", {"name": "Mac"})
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            key = base64.b64encode(os.urandom(16)).decode()
            writer.write(
                (
                    "GET /v1/ws HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode()
            )
            await writer.drain()
            opened = await server.read_http(reader)
            self.assertIn(" 101 ", opened[0])
            sock = Socket(reader, writer)
            sock.stream = server.ByteStream(reader, opened[3])
            await sock.send({"op": "app", "kind": "status"})
            with self.assertRaises((EOFError, ConnectionError, OSError, asyncio.IncompleteReadError)):
                await asyncio.wait_for(sock.recv_frame(), 2)
        finally:
            await self._stop(holder)


class BookmarkRoomTests(unittest.IsolatedAsyncioTestCase):
    async def test_bookmark_room_put_get_revision_and_isolation(self):
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
                holder["state"] = state
                holder["port"] = tcp.sockets[0].getsockname()[1]
                bound.set()
                async with tcp:
                    await tcp.serve_forever()

            task = asyncio.create_task(boot())
            await asyncio.wait_for(bound.wait(), 3)
            port = holder["port"]
            try:
                room_id = "a" * 64
                verifier = "b" * 64
                cipher = base64.b64encode(b"opaque-bookmark-blob").decode()
                status, payload = await http(
                    port,
                    "PUT",
                    f"/v1/bookmark-rooms/{room_id}",
                    {
                        "room_id": room_id,
                        "verifier": verifier,
                        "ciphertext": cipher,
                        "revision": 1,
                        "expected_revision": 0,
                    },
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload["revision"], 1)
                self.assertEqual(payload["ciphertext"], cipher)

                status, got = await http(
                    port,
                    "GET",
                    f"/v1/bookmark-rooms/{room_id}",
                    extra_headers={"X-Tocode-Bookmark-Verifier": verifier},
                )
                self.assertEqual(status, 200)
                self.assertEqual(got["ciphertext"], cipher)

                status, _ = await http(
                    port,
                    "GET",
                    f"/v1/bookmark-rooms/{room_id}",
                    extra_headers={"X-Tocode-Bookmark-Verifier": "c" * 64},
                )
                self.assertEqual(status, 401)

                status, conflict = await http(
                    port,
                    "PUT",
                    f"/v1/bookmark-rooms/{room_id}",
                    {
                        "verifier": verifier,
                        "ciphertext": cipher,
                        "revision": 1,
                        "expected_revision": 0,
                    },
                )
                self.assertEqual(status, 409)
                self.assertEqual(conflict["error"], "revision_conflict")

                status, ok = await http(
                    port,
                    "PUT",
                    f"/v1/bookmark-rooms/{room_id}",
                    {
                        "verifier": verifier,
                        "ciphertext": cipher + "x",
                        "revision": 2,
                        "expected_revision": 1,
                    },
                )
                self.assertEqual(status, 200)
                self.assertEqual(ok["revision"], 2)

                routes_path = pathlib.Path(data)
                if routes_path.exists():
                    blob = routes_path.read_text(encoding="utf-8")
                    self.assertNotIn(cipher, blob)
                    self.assertNotIn("ciphertext", blob)
                    self.assertNotIn(verifier, blob)
                rooms_path = pathlib.Path(directory) / "bookmark-rooms.json"
                self.assertTrue(rooms_path.is_file())
                rooms = json.loads(rooms_path.read_text(encoding="utf-8"))
                self.assertEqual(rooms["rooms"][0]["room_id"], room_id)
                self.assertEqual(rooms["rooms"][0]["verifier"], verifier)
            finally:
                holder["server"].close()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass


if __name__ == "__main__":
    unittest.main()

