"""Tocode 文字与文件中转。

只保存设备与关联的路由，以及内存中的短期配对码。
文件字节只在内存中转发，不写入路由文件。
不写入角色提示词、模型密钥、微信凭据或消息正文。
生产环境用 --cert 与 --key 启用 TLS。
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import ssl
import time
import uuid
from pathlib import Path

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PAIRING_TTL = 180
TEXT_LIMIT = 8000
FILE_LIMIT = 20 * 1024 * 1024
FORBIDDEN_FIELDS = {
    "prompt",
    "bot_token",
    "api_key",
    "wechat_token",
    "context_token",
    "authorization",
}
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class RelayError(Exception):
    def __init__(self, status: int, code: str):
        self.status = status
        self.code = code


class Connection:
    def __init__(self, writer: asyncio.StreamWriter, side: str, owner: str):
        self.writer = writer
        self.side = side
        self.owner = owner
        self.lock = asyncio.Lock()
        self.pending_file = None

    async def send(self, payload: dict) -> None:
        await self.send_bytes(1, json.dumps(payload, ensure_ascii=False).encode())

    async def send_bytes(self, opcode: int, payload: bytes) -> None:
        if self.writer.is_closing():
            raise ConnectionError("closed")
        frame = encode_frame(opcode, payload)
        async with self.lock:
            self.writer.write(frame)
            try:
                timeout = 0.5 if len(payload) < 65536 else min(60, 1 + len(payload) / (256 * 1024))
                await asyncio.wait_for(self.writer.drain(), timeout)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                self.writer.close()
                raise ConnectionError("closed")


class RelayState:
    def __init__(self, data_path: str | None):
        self.data_path = data_path
        self.devices: dict[str, dict] = {}
        self.links: dict[str, dict] = {}
        self.pairings: dict[str, dict] = {}
        self.mac_sockets: dict[str, Connection] = {}
        self.android_sockets: dict[str, Connection] = {}
        self.stored_messages: list = []
        if data_path:
            self._load()

    def register_device(self, name: str) -> dict:
        device_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(24)
        self.devices[token] = {"id": device_id, "name": name or "Mac", "token": token}
        self._save()
        return {"device_id": device_id, "device_token": token}

    def device_for_token(self, token: str) -> dict | None:
        for saved, device in self.devices.items():
            if hmac.compare_digest(saved, token):
                return device
        return None

    def create_pairing(self, token: str, body: dict) -> dict:
        self._reject_forbidden(body)
        device = self.device_for_token(token)
        if device is None:
            raise RelayError(401, "unauthorized")
        role_id = str(body.get("role_id") or "").strip()
        role_name = str(body.get("role_name") or "").strip()
        display_name = str(body.get("display_name") or role_name).strip()
        if not role_id or not role_name or not display_name:
            raise RelayError(400, "missing_role")
        self._purge_pairings()
        code = self._new_code()
        self.pairings[code] = {
            "code": code,
            "device_token": token,
            "device_id": device["id"],
            "role_id": role_id,
            "role_name": role_name,
            "display_name": display_name,
            "expires_at": time.time() + PAIRING_TTL,
            "link_id": None,
        }
        return {"code": code, "expires_at": int(self.pairings[code]["expires_at"])}

    def pairing_status(self, token: str, code: str) -> dict:
        device = self.device_for_token(token)
        pairing = self.pairings.get(code)
        if device is None or pairing is None or pairing["device_id"] != device["id"]:
            raise RelayError(404, "not_found")
        if pairing["link_id"]:
            link = self.links[pairing["link_id"]]
            return {"status": "redeemed", "link": self._public_link(link)}
        if time.time() >= pairing["expires_at"]:
            return {"status": "expired"}
        return {"status": "pending"}

    def redeem(self, code: str, body: dict) -> dict:
        self._reject_forbidden(body)
        pairing = self.pairings.get(code)
        if pairing is None:
            raise RelayError(404, "not_found")
        if pairing["link_id"]:
            raise RelayError(409, "used")
        if time.time() >= pairing["expires_at"]:
            raise RelayError(410, "expired")
        android_id = str(body.get("android_id") or "").strip()
        android_name = str(body.get("android_name") or "Android").strip()
        if not android_id:
            raise RelayError(400, "missing_android")
        link_id = str(uuid.uuid4())
        link_token = secrets.token_urlsafe(24)
        device = self.devices[pairing["device_token"]]
        link = {
            "id": link_id,
            "device_id": pairing["device_id"],
            "device_name": device["name"],
            "role_id": pairing["role_id"],
            "role_name": pairing["role_name"],
            "display_name": pairing["display_name"],
            "android_id": android_id,
            "android_name": android_name,
            "link_token": link_token,
        }
        self.links[link_id] = link
        pairing["link_id"] = link_id
        self._save()
        public = self._public_link(link)
        public["link_token"] = link_token
        return public

    def update_link(self, token: str, link_id: str, body: dict) -> dict:
        self._reject_forbidden(body)
        link = self._owned_link(token, link_id)
        role_id = str(body.get("role_id") or link["role_id"]).strip()
        role_name = str(body.get("role_name") or link["role_name"]).strip()
        display_name = str(body.get("display_name") or link["display_name"]).strip()
        if not role_id or not role_name or not display_name:
            raise RelayError(400, "missing_role")
        link["role_id"] = role_id
        link["role_name"] = role_name
        link["display_name"] = display_name
        self._save()
        return self._public_link(link)

    def delete_link(self, token: str, link_id: str) -> None:
        self._owned_link(token, link_id)
        self.links.pop(link_id, None)
        self._save()

    def identify(self, token: str) -> tuple[str, str] | None:
        device = self.device_for_token(token)
        if device is not None:
            return ("mac", device["id"])
        for link in self.links.values():
            if hmac.compare_digest(link["link_token"], token):
                return ("android", link["id"])
        return None

    def links_for_device(self, device_id: str) -> list[str]:
        return [link["id"] for link in self.links.values() if link["device_id"] == device_id]

    def _owned_link(self, token: str, link_id: str) -> dict:
        device = self.device_for_token(token)
        link = self.links.get(link_id)
        if device is None or link is None or link["device_id"] != device["id"]:
            raise RelayError(404, "not_found")
        return link

    def _public_link(self, link: dict) -> dict:
        return {
            "link_id": link["id"],
            "device_name": link["device_name"],
            "role_id": link["role_id"],
            "role_name": link["role_name"],
            "display_name": link["display_name"],
            "android_id": link["android_id"],
            "android_name": link["android_name"],
        }

    def _new_code(self) -> str:
        while True:
            code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
            if code not in self.pairings:
                return code

    def _purge_pairings(self) -> None:
        now = time.time()
        stale = [
            code
            for code, pairing in self.pairings.items()
            if pairing["link_id"] is None and pairing["expires_at"] <= now
        ]
        for code in stale:
            self.pairings.pop(code, None)

    def _reject_forbidden(self, body: dict) -> None:
        if any(key in body for key in FORBIDDEN_FIELDS):
            raise RelayError(400, "forbidden_field")

    def _load(self) -> None:
        path = Path(self.data_path)
        if not path.exists():
            return
        raw = json.loads(path.read_text(encoding="utf-8"))
        for device in raw.get("devices", []):
            self.devices[device["token"]] = device
        for link in raw.get("links", []):
            self.links[link["id"]] = link

    def _save(self) -> None:
        if not self.data_path:
            return
        path = Path(self.data_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        payload = {
            "devices": list(self.devices.values()),
            "links": list(self.links.values()),
        }
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.chmod(path, 0o600)


class ByteStream:
    def __init__(self, reader: asyncio.StreamReader, leftover: bytes):
        self.reader = reader
        self.buf = leftover

    async def readexactly(self, count: int) -> bytes:
        while len(self.buf) < count:
            chunk = await self.reader.read(max(4096, count - len(self.buf)))
            if not chunk:
                raise EOFError
            self.buf += chunk
        out, self.buf = self.buf[:count], self.buf[count:]
        return out


def encode_frame(opcode: int, payload: bytes) -> bytes:
    header = bytes([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header += bytes([length])
    elif length < 65536:
        header += bytes([126]) + length.to_bytes(2, "big")
    else:
        header += bytes([127]) + length.to_bytes(8, "big")
    return header + payload


async def read_frame(stream: ByteStream) -> tuple[int, bytes]:
    header = await stream.readexactly(2)
    opcode = header[0] & 0x0F
    masked = header[1] & 0x80
    length = header[1] & 0x7F
    if length == 126:
        length = int.from_bytes(await stream.readexactly(2), "big")
    elif length == 127:
        length = int.from_bytes(await stream.readexactly(8), "big")
    if length > FILE_LIMIT:
        raise ValueError("frame")
    mask = await stream.readexactly(4) if masked else b""
    payload = await stream.readexactly(length)
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


async def read_http(reader: asyncio.StreamReader):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(4096)
        if not chunk:
            return None
        data += chunk
        if len(data) > 65536:
            return None
    head, rest = data.split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.lower()] = value.strip()
    length = int(headers.get("content-length", "0") or "0")
    while len(rest) < length:
        chunk = await reader.read(length - len(rest))
        if not chunk:
            break
        rest += chunk
    body, leftover = rest[:length], rest[length:]
    return lines[0], headers, body, leftover


def http_response(status: int, payload: dict) -> bytes:
    raw = json.dumps(payload, ensure_ascii=False).encode()
    reason = {
        200: "OK",
        400: "Bad Request",
        401: "Unauthorized",
        404: "Not Found",
        409: "Conflict",
        410: "Gone",
    }.get(status, "Error")
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(raw)}\r\n"
        "Connection: close\r\n\r\n"
    )
    return head.encode() + raw


def bearer(headers: dict) -> str:
    value = headers.get("authorization", "")
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return ""


def query_token(target: str) -> str:
    _, _, query = target.partition("?")
    for part in query.split("&"):
        key, _, value = part.partition("=")
        if key == "token":
            return value
    return ""


async def dispatch(reader, writer, state: RelayState) -> None:
    opened = await read_http(reader)
    if opened is None:
        writer.close()
        return
    request, headers, body, leftover = opened
    try:
        method, target, _ = request.split(" ", 2)
    except ValueError:
        writer.close()
        return
    path = target.split("?", 1)[0]
    if headers.get("upgrade", "").lower() == "websocket":
        await serve_socket(reader, writer, state, target, headers, leftover)
        return
    try:
        payload = json.loads(body.decode()) if body else {}
        if not isinstance(payload, dict):
            raise RelayError(400, "bad_json")
        result, status = route_http(state, method, path, headers, payload)
    except RelayError as error:
        result, status = {"error": error.code}, error.status
    except json.JSONDecodeError:
        result, status = {"error": "bad_json"}, 400
    writer.write(http_response(status, result))
    await writer.drain()
    writer.close()


def route_http(state: RelayState, method: str, path: str, headers: dict, body: dict):
    token = bearer(headers)
    if method == "GET" and path == "/health":
        return {"ok": True}, 200
    if method == "POST" and path == "/v1/devices":
        return state.register_device(str(body.get("name") or "Mac")), 200
    if method == "POST" and path == "/v1/pairings":
        return state.create_pairing(token, body), 200
    if method == "GET" and path.startswith("/v1/pairings/"):
        code = path.removeprefix("/v1/pairings/")
        return state.pairing_status(token, code), 200
    if method == "POST" and path.startswith("/v1/pairings/") and path.endswith("/redeem"):
        code = path.removeprefix("/v1/pairings/").removesuffix("/redeem").strip("/")
        return state.redeem(code, body), 200
    if method == "PATCH" and path.startswith("/v1/links/"):
        return state.update_link(token, path.removeprefix("/v1/links/"), body), 200
    if method == "DELETE" and path.startswith("/v1/links/"):
        state.delete_link(token, path.removeprefix("/v1/links/"))
        return {"ok": True}, 200
    raise RelayError(404, "not_found")


async def serve_socket(reader, writer, state: RelayState, target: str, headers: dict, leftover: bytes):
    token = query_token(target)
    identity = state.identify(token)
    if identity is None or path_of(target) != "/v1/ws":
        writer.write(http_response(401, {"error": "unauthorized"}))
        await writer.drain()
        writer.close()
        return
    accept = base64.b64encode(
        hashlib.sha1((headers.get("sec-websocket-key", "") + WS_GUID).encode()).digest()
    ).decode()
    writer.write(
        (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode()
    )
    await writer.drain()
    side, owner = identity
    connection = Connection(writer, side, owner)
    if side == "mac":
        previous = state.mac_sockets.get(owner)
        state.mac_sockets[owner] = connection
        ready = {"op": "ready", "side": "mac", "link_ids": state.links_for_device(owner)}
    else:
        previous = state.android_sockets.get(owner)
        state.android_sockets[owner] = connection
        ready = {"op": "ready", "side": "android", "link_id": owner}
    if previous is not None and previous is not connection:
        previous.writer.close()
    try:
        await connection.send(ready)
        stream = ByteStream(reader, leftover)
        while True:
            opcode, payload = await read_frame(stream)
            if opcode == 8:
                break
            if opcode == 9:
                async with connection.lock:
                    writer.write(encode_frame(10, payload))
                    await writer.drain()
                continue
            if opcode == 2:
                await on_file_bytes(state, connection, payload)
                continue
            if opcode != 1:
                continue
            if connection.pending_file is not None:
                connection.pending_file = None
                await connection.send({
                    "op": "error",
                    "code": "bad_op",
                    "message": "文件帧不完整",
                })
            await on_text(state, connection, payload.decode())
    except (EOFError, ConnectionError, asyncio.IncompleteReadError, ValueError, json.JSONDecodeError):
        pass
    finally:
        if side == "mac" and state.mac_sockets.get(owner) is connection:
            state.mac_sockets.pop(owner, None)
        if side == "android" and state.android_sockets.get(owner) is connection:
            state.android_sockets.pop(owner, None)
        writer.close()


def path_of(target: str) -> str:
    return target.split("?", 1)[0]


def file_size(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def safe_file_name(name: str) -> bool:
    return (
        bool(name)
        and len(name) <= 255
        and "/" not in name
        and "\\" not in name
        and "\0" not in name
        and name not in {".", ".."}
    )


async def begin_file(state: RelayState, connection: Connection, message: dict, op: str, link_id: str, message_id: str) -> None:
    size = file_size(message.get("size"))
    name = str(message.get("name") or "")
    kind = message.get("kind")
    caption = message.get("text") or ""
    if not isinstance(caption, str):
        caption = None
    valid = (
        bool(message_id)
        and size is not None
        and 0 < size <= FILE_LIMIT
        and safe_file_name(name)
        and kind in {"image", "file"}
        and caption is not None
        and len(caption) <= TEXT_LIMIT
    )
    link = state.links.get(link_id)
    error = None
    forward = None
    if not valid:
        error = {"op": "error", "code": "empty", "message_id": message_id, "message": "只接受不超过 20MB 的单个文件"}
    elif link is None:
        error = {"op": "error", "code": "unknown_link", "message_id": message_id, "message": "关联不存在"}
    elif connection.side == "android" and op == "file":
        if connection.owner != link_id:
            error = {"op": "error", "code": "forbidden", "message_id": message_id, "message": "不能转发别人的关联"}
        elif state.mac_sockets.get(link["device_id"]) is None:
            error = {"op": "error", "code": "mac_offline", "message_id": message_id, "message": "Mac 不在线"}
        else:
            forward = {
                "op": "inbound_file",
                "link_id": link_id,
                "message_id": message_id,
                "name": name,
                "size": size,
                "kind": kind,
                "text": caption,
                "android_id": link["android_id"],
                "peer": "mac",
                "peer_id": link["device_id"],
            }
    elif connection.side == "mac" and op == "file_reply":
        if link["device_id"] != connection.owner:
            error = {"op": "error", "code": "forbidden", "message_id": message_id, "message": "不能回复别人的关联"}
        elif state.android_sockets.get(link_id) is None:
            error = {"op": "error", "code": "android_offline", "message_id": message_id, "message": "安卓不在线"}
        else:
            forward = {
                "op": "file",
                "link_id": link_id,
                "message_id": message_id,
                "name": name,
                "size": size,
                "kind": kind,
                "text": caption,
                "peer": "android",
                "peer_id": link_id,
            }
    else:
        error = {"op": "error", "code": "bad_op", "message_id": message_id, "message": "无法处理"}
    if error is not None:
        await connection.send(error)
    if size is not None and 0 < size <= FILE_LIMIT:
        connection.pending_file = {"size": size, "forward": forward, "message_id": message_id}
    elif forward is not None:
        connection.pending_file = None


async def on_file_bytes(state: RelayState, connection: Connection, payload: bytes) -> None:
    pending = connection.pending_file
    connection.pending_file = None
    if pending is None:
        await connection.send({"op": "error", "code": "bad_op", "message": "没有对应的文件头"})
        return
    if len(payload) != pending["size"]:
        await connection.send({
            "op": "error",
            "code": "empty",
            "message_id": pending["message_id"],
            "message": "文件长度不匹配",
        })
        return
    forward = pending["forward"]
    if forward is None:
        return
    peer = state.mac_sockets.get(forward["peer_id"]) if forward["peer"] == "mac" else state.android_sockets.get(forward["peer_id"])
    header = {key: value for key, value in forward.items() if key not in {"peer", "peer_id"}}
    try:
        if peer is None:
            raise ConnectionError("closed")
        await peer.send(header)
        await peer.send_bytes(2, payload)
    except Exception:
        if forward["peer"] == "mac":
            state.mac_sockets.pop(forward["peer_id"], None)
            code, message = "mac_offline", "Mac 不在线"
        else:
            state.android_sockets.pop(forward["peer_id"], None)
            code, message = "android_offline", "安卓不在线"
        await connection.send({
            "op": "error",
            "code": code,
            "message_id": pending["message_id"],
            "message": message,
        })
        return
    await connection.send({"op": "accepted", "message_id": pending["message_id"]})


async def on_text(state: RelayState, connection: Connection, raw: str) -> None:
    message = json.loads(raw)
    if any(key in message for key in FORBIDDEN_FIELDS):
        await connection.send({"op": "error", "code": "forbidden_field", "message": "不能携带密钥或提示词"})
        return
    op = message.get("op")
    link_id = str(message.get("link_id") or "")
    message_id = str(message.get("message_id") or "")
    if op in {"file", "file_reply"}:
        await begin_file(state, connection, message, op, link_id, message_id)
        return
    text = message.get("text")
    if op not in {"text", "reply"} or not message_id:
        await connection.send({"op": "error", "code": "bad_op", "message_id": message_id, "message": "无法处理"})
        return
    if not isinstance(text, str) or not text.strip() or len(text) > TEXT_LIMIT:
        await connection.send({"op": "error", "code": "empty", "message_id": message_id, "message": "只接受一段文字"})
        return
    link = state.links.get(link_id)
    if link is None:
        await connection.send({"op": "error", "code": "unknown_link", "message_id": message_id, "message": "关联不存在"})
        return
    if connection.side == "android" and op == "text":
        if connection.owner != link_id:
            await connection.send({"op": "error", "code": "forbidden", "message_id": message_id, "message": "不能转发别人的关联"})
            return
        peer = state.mac_sockets.get(link["device_id"])
        if peer is None:
            await connection.send({"op": "error", "code": "mac_offline", "message_id": message_id, "message": "Mac 不在线"})
            return
        try:
            await peer.send({
                "op": "inbound",
                "link_id": link_id,
                "message_id": message_id,
                "text": text,
                "android_id": link["android_id"],
            })
        except Exception:
            state.mac_sockets.pop(link["device_id"], None)
            await connection.send({"op": "error", "code": "mac_offline", "message_id": message_id, "message": "Mac 不在线"})
            return
        await connection.send({"op": "accepted", "message_id": message_id})
        return
    if connection.side == "mac" and op == "reply":
        if link["device_id"] != connection.owner:
            await connection.send({"op": "error", "code": "forbidden", "message_id": message_id, "message": "不能回复别人的关联"})
            return
        peer = state.android_sockets.get(link_id)
        if peer is None:
            await connection.send({"op": "error", "code": "android_offline", "message_id": message_id, "message": "安卓不在线"})
            return
        try:
            await peer.send({
                "op": "reply",
                "link_id": link_id,
                "message_id": message_id,
                "text": text,
            })
        except Exception:
            state.android_sockets.pop(link_id, None)
            await connection.send({"op": "error", "code": "android_offline", "message_id": message_id, "message": "安卓不在线"})
            return
        await connection.send({"op": "accepted", "message_id": message_id})
        return
    await connection.send({"op": "error", "code": "bad_op", "message_id": message_id, "message": "无法处理"})


async def handle(reader, writer, state: RelayState) -> None:
    try:
        await dispatch(reader, writer, state)
    except Exception:
        try:
            writer.close()
        except Exception:
            pass


async def serve(host: str, port: int, data_path: str | None, cert: str, key: str) -> None:
    state = RelayState(data_path)
    ssl_context = None
    if cert and key:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert, key)
    server = await asyncio.start_server(
        lambda reader, writer: handle(reader, writer, state),
        host,
        port,
        ssl=ssl_context,
    )
    bound = server.sockets[0].getsockname()
    print(f"READY {bound[0]} {bound[1]}", flush=True)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Tocode 文字中转")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--data", default="")
    parser.add_argument("--cert", default="")
    parser.add_argument("--key", default="")
    args = parser.parse_args()
    asyncio.run(serve(args.host, args.port, args.data or None, args.cert, args.key))


if __name__ == "__main__":
    main()
