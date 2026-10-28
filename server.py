"""Tocode 安卓遥控中转。

只保存设备与关联的路由，以及内存中的短期配对码。
动作、结果、手机对话、目录和附件都只在内存中转发，不写入路由文件。
不写入角色、提示词、模型密钥、微信凭据或命令正文。
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
import re
import secrets
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_AUTH_TIMEOUT = 5.0
# Transition: accept legacy ?token= until all clients send first-frame auth. Set False at cutover.
WS_ALLOW_QUERY_TOKEN = False
DIAG_BLOCKED = {
    "token", "device_token", "link_token", "authorization", "binding_key",
    "binding_key_digest", "text", "content", "body", "path", "caption",
    "bytes", "data", "password", "secret", "prompt", "api_key", "bot_token",
    "verifier", "ciphertext", "room_id",
}
BOOKMARK_CIPHERTEXT_MAX = 4_194_304
BOOKMARK_ROOM_ID_RE = re.compile(r"^[0-9a-f]{64}$")
BOOKMARK_VERIFIER_RE = re.compile(r"^[0-9a-f]{64}$")
_diag_lock = threading.Lock()
_diag_dir: Path | None = None


def configure_diag(path: str | None) -> None:
    global _diag_dir
    if path:
        _diag_dir = Path(path)
    else:
        env = os.environ.get("TOCODE_DIAG_DIR", "").strip()
        _diag_dir = Path(env) if env else Path("diagnostics")


def diag(event: str, **fields) -> None:
    """本地 JSONL 诊断；永不写 token/正文。失败静默。"""
    if _diag_dir is None:
        return
    row = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "side": "relay",
        "event": event,
    }
    detail = {}
    for key, value in fields.items():
        lower = key.lower()
        if lower in DIAG_BLOCKED or "token" in lower or "secret" in lower or "password" in lower:
            continue
        if key in {"link_id", "device_id", "corr", "request_id"}:
            if isinstance(value, str) and value:
                row[key] = value[:128]
            continue
        if value is None:
            continue
        if isinstance(value, (bool, int, float)):
            detail[key] = value
        elif isinstance(value, str):
            detail[key] = value[:240]
        else:
            detail[key] = str(value)[:80]
    if detail:
        row["detail"] = detail
    line = json.dumps(row, ensure_ascii=False) + "\n"
    try:
        with _diag_lock:
            _diag_dir.mkdir(parents=True, exist_ok=True)
            day = datetime.now(timezone.utc).strftime("%Y%m%d")
            target = _diag_dir / f"relay-{day}.jsonl"
            if target.exists() and target.stat().st_size > 8 * 1024 * 1024:
                return
            with target.open("a", encoding="utf-8") as handle:
                handle.write(line)
            _prune_diag(_diag_dir)
    except Exception:
        return


def _prune_diag(folder: Path) -> None:
    cutoff = time.time() - 7 * 86400
    try:
        for item in folder.glob("relay-*.jsonl"):
            if item.stat().st_mtime < cutoff:
                item.unlink(missing_ok=True)
    except Exception:
        return
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
ACTIONS = {
    "desktops",
    "desktop-switch",
    "remote-buttons",
    "remote-press",
}
APP_KINDS = {
    "status", "sessions", "session_create", "messages", "chat", "tree",
    "profiles", "profile_select", "projects", "project_create", "folders",
    "session_delete", "session_rename", "preview", "download",
    "models", "model_select",
}
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,199}$")
PROVIDER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
APP_FIELDS = {"op", "request_id", "kind", "session_id", "title", "text", "profile", "project_id", "path", "offset", "cursor"}
CURSOR_RE = re.compile(r"^(tail|older):[0-9]{1,20}$")
PATH_LIMIT = 1024
PATH_KINDS = {"folders", "project_create", "preview", "tree"}
PREVIEW_RESULT_LIMIT = 1_500_000
PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
PROJECT_RE = re.compile(r"^p_[A-Za-z0-9_-]{1,64}$")
PROJECT_FILE_FIELDS = {"op", "request_id", "name", "size", "kind", "profile", "project_id", "hold"}
PLACE_FIELDS = {"op", "request_id", "hold_id", "profile", "project_id"}
DROP_FIELDS = {"op", "request_id", "hold_id"}
HOLD_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ATTACHMENT_PREFIXES = ("对话附件-图片/", "对话附件-文件/")
APP_RESULT_LIMIT = 24000


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


class BookmarkRoomStore:
    """书签密文房间：与 routes.json 分开，只存 room_id / verifier / ciphertext / revision。"""

    def __init__(self, data_path: str | None):
        self.path: Path | None = None
        self.rooms: dict[str, dict] = {}
        if data_path:
            self.path = Path(data_path).with_name("bookmark-rooms.json")
            self._load()

    def get(self, room_id: str, verifier: str) -> dict:
        room = self.rooms.get(room_id)
        if room is None:
            raise RelayError(404, "not_found")
        if not hmac.compare_digest(str(room.get("verifier") or ""), verifier):
            raise RelayError(401, "unauthorized")
        return {
            "room_id": room_id,
            "ciphertext": room["ciphertext"],
            "revision": int(room["revision"]),
        }

    def put(self, room_id: str, body: dict) -> dict:
        verifier = str(body.get("verifier") or "").strip().lower()
        ciphertext = str(body.get("ciphertext") or "")
        if not BOOKMARK_VERIFIER_RE.match(verifier):
            raise RelayError(400, "bad_verifier")
        if not ciphertext or len(ciphertext.encode("utf-8")) > BOOKMARK_CIPHERTEXT_MAX:
            raise RelayError(400, "bad_ciphertext")
        try:
            revision = int(body.get("revision"))
            expected = int(body.get("expected_revision"))
        except (TypeError, ValueError):
            raise RelayError(400, "bad_revision") from None
        if revision < 1 or expected < 0 or revision != expected + 1:
            raise RelayError(400, "bad_revision")

        existing = self.rooms.get(room_id)
        if existing is None:
            if expected != 0:
                raise RelayError(409, "revision_conflict")
        else:
            if not hmac.compare_digest(str(existing.get("verifier") or ""), verifier):
                raise RelayError(401, "unauthorized")
            if int(existing["revision"]) != expected:
                raise RelayError(409, "revision_conflict")

        self.rooms[room_id] = {
            "room_id": room_id,
            "verifier": verifier,
            "ciphertext": ciphertext,
            "revision": revision,
        }
        self._save()
        return {
            "room_id": room_id,
            "ciphertext": ciphertext,
            "revision": revision,
        }

    def _load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        for room in raw.get("rooms", []):
            room_id = str(room.get("room_id") or "")
            if BOOKMARK_ROOM_ID_RE.match(room_id):
                self.rooms[room_id] = room

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        payload = {"rooms": list(self.rooms.values())}
        self.path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.chmod(self.path, 0o600)


class RelayState:
    def __init__(self, data_path: str | None):
        self.data_path = data_path
        self.devices: dict[str, dict] = {}
        self.links: dict[str, dict] = {}
        self.pairings: dict[str, dict] = {}
        self.mac_sockets: dict[str, Connection] = {}
        self.android_sockets: dict[str, Connection] = {}
        self.stored_messages: list = []
        self.bookmark_rooms = BookmarkRoomStore(data_path)
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
        if "binding_key" in body:
            raise RelayError(400, "forbidden_field")
        device = self.device_for_token(token)
        if device is None:
            raise RelayError(401, "unauthorized")
        digest = str(body.get("binding_key_digest") or "").strip().lower()
        if not digest or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise RelayError(400, "missing_binding_key_digest")
        self._purge_pairings()
        code = self._new_code()
        self.pairings[code] = {
            "code": code,
            "device_token": token,
            "device_id": device["id"],
            "expires_at": time.time() + PAIRING_TTL,
            "link_id": None,
            "binding_key_digest": digest,
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
        binding_key = str(body.get("binding_key") or "")
        if not binding_key:
            raise RelayError(401, "unauthorized")
        expected = str(pairing.get("binding_key_digest") or "")
        presented = hashlib.sha256(binding_key.encode("utf-8")).hexdigest()
        if not expected or not hmac.compare_digest(presented, expected):
            raise RelayError(401, "unauthorized")
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
            "android_id": android_id,
            "android_name": android_name,
            "link_token": link_token,
        }
        self.links[link_id] = link
        pairing["link_id"] = link_id
        pairing.pop("binding_key_digest", None)
        self._save()
        public = self._public_link(link)
        public["link_token"] = link_token
        return public

    def take_link(self, token: str, link_id: str) -> dict:
        link = self.links.get(link_id)
        if link is None or not self._can_manage(token, link):
            raise RelayError(404, "not_found")
        self.links.pop(link_id, None)
        self._save()
        return link

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

    def _can_manage(self, token: str, link: dict) -> bool:
        device = self.device_for_token(token)
        if device is not None and link["device_id"] == device["id"]:
            return True
        return hmac.compare_digest(link["link_token"], token)

    def _public_link(self, link: dict) -> dict:
        return {
            "link_id": link["id"],
            "device_name": link["device_name"],
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


def browser_pair_cors(method: str, path: str) -> bool:
    """Allow browsers to redeem pairing codes and unlink; other routes stay closed."""
    if method == "OPTIONS":
        if path.startswith("/v1/pairings/") and path.endswith("/redeem"):
            return True
        if path.startswith("/v1/links/") and path != "/v1/links/":
            return True
        return False
    if method == "POST" and path.startswith("/v1/pairings/") and path.endswith("/redeem"):
        return True
    if method == "DELETE" and path.startswith("/v1/links/") and path != "/v1/links/":
        return True
    return False


def http_response(status: int, payload: dict, cors: bool = False) -> bytes:
    raw = json.dumps(payload, ensure_ascii=False).encode()
    reason = {
        200: "OK",
        204: "No Content",
        400: "Bad Request",
        401: "Unauthorized",
        404: "Not Found",
        409: "Conflict",
        410: "Gone",
    }.get(status, "Error")
    cors_headers = ""
    if cors:
        cors_headers = (
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: POST, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
            "Access-Control-Max-Age: 86400\r\n"
        )
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(raw)}\r\n"
        f"{cors_headers}"
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
    cors = browser_pair_cors(method, path)
    if method == "OPTIONS" and cors:
        writer.write(http_response(204, {}, cors=True))
        await writer.drain()
        writer.close()
        return
    if method == "DELETE" and path.startswith("/v1/links/"):
        try:
            removed = state.take_link(bearer(headers), path.removeprefix("/v1/links/"))
            await notify_revoked(state, removed)
            result, status = {"ok": True}, 200
        except RelayError as error:
            result, status = {"error": error.code}, error.status
        writer.write(http_response(status, result, cors=cors))
        await writer.drain()
        writer.close()
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
    writer.write(http_response(status, result, cors=cors))
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
    if path.startswith("/v1/bookmark-rooms/"):
        room_id = path.removeprefix("/v1/bookmark-rooms/").strip("/")
        if not BOOKMARK_ROOM_ID_RE.match(room_id):
            raise RelayError(400, "bad_room_id")
        if method == "GET":
            verifier = str(headers.get("x-tocode-bookmark-verifier") or "").strip().lower()
            if not BOOKMARK_VERIFIER_RE.match(verifier):
                raise RelayError(401, "unauthorized")
            return state.bookmark_rooms.get(room_id, verifier), 200
        if method == "PUT":
            if str(body.get("room_id") or "") and str(body.get("room_id")) != room_id:
                raise RelayError(400, "bad_room_id")
            return state.bookmark_rooms.put(room_id, body), 200
    raise RelayError(404, "not_found")


async def await_ws_auth(stream: ByteStream, state: RelayState):
    """First text frame must be {op:auth,token}. Returns (side, owner) or None."""
    try:
        opcode, payload = await asyncio.wait_for(read_frame(stream), timeout=WS_AUTH_TIMEOUT)
    except (asyncio.TimeoutError, EOFError, asyncio.IncompleteReadError, ValueError, ConnectionError):
        return None
    if opcode == 8:
        return None
    if opcode != 1:
        return None
    try:
        body = json.loads(payload.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(body, dict) or body.get("op") != "auth":
        return None
    token = str(body.get("token") or "")
    if not token:
        return None
    return state.identify(token)


async def serve_socket(reader, writer, state: RelayState, target: str, headers: dict, leftover: bytes):
    if path_of(target) != "/v1/ws":
        writer.write(http_response(401, {"error": "unauthorized"}))
        await writer.drain()
        writer.close()
        return
    query = query_token(target)
    identity = None
    if query:
        if not WS_ALLOW_QUERY_TOKEN:
            writer.write(http_response(401, {"error": "unauthorized"}))
            await writer.drain()
            writer.close()
            return
        identity = state.identify(query)
        if identity is None:
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
    stream = ByteStream(reader, leftover)
    if identity is None:
        identity = await await_ws_auth(stream, state)
        if identity is None:
            diag("ws.auth_fail", reason="auth_timeout_or_bad")
            writer.close()
            return
    side, owner = identity
    connection = Connection(writer, side, owner)
    close_reason = "unknown"
    ua = str(headers.get("user-agent") or "")[:120]
    if side == "mac":
        previous = state.mac_sockets.get(owner)
        state.mac_sockets[owner] = connection
        ready = {"op": "ready", "side": "mac", "link_ids": state.links_for_device(owner)}
        diag("ws.accept", device_id=owner, side_peer="mac", links=len(ready["link_ids"]), ua=ua)
    else:
        previous = state.android_sockets.get(owner)
        state.android_sockets[owner] = connection
        ready = {"op": "ready", "side": "android", "link_id": owner}
        diag("ws.accept", link_id=owner, side_peer="android", ua=ua)
    if previous is not None and previous is not connection:
        diag("ws.replace", device_id=owner if side == "mac" else "", link_id=owner if side == "android" else "", side_peer=side)
        previous.writer.close()
    try:
        await connection.send(ready)
        while True:
            opcode, payload = await read_frame(stream)
            if opcode == 8:
                close_reason = "ws_close"
                break
            if opcode == 9:
                async with connection.lock:
                    writer.write(encode_frame(10, payload))
                    await writer.drain()
                continue
            if opcode == 2:
                if connection.pending_file is None:
                    await connection.send({"op": "error", "code": "bad_op", "message": "不接受二进制"})
                    continue
                await on_file_bytes(state, connection, payload)
                continue
            if opcode != 1:
                continue
            if connection.pending_file is not None:
                pending = connection.pending_file
                connection.pending_file = None
                await connection.send({
                    "op": "error",
                    "code": "bad_op",
                    "request_id": pending.get("message_id", ""),
                    "message": "文件帧不完整",
                })
            await on_text(state, connection, payload.decode())
    except EOFError:
        close_reason = "eof"
    except ConnectionError:
        close_reason = "connection_error"
    except asyncio.IncompleteReadError:
        close_reason = "incomplete_read"
    except ValueError:
        close_reason = "frame_error"
    except json.JSONDecodeError:
        close_reason = "json_error"
    finally:
        if side == "mac" and state.mac_sockets.get(owner) is connection:
            state.mac_sockets.pop(owner, None)
            diag("ws.close", device_id=owner, reason=close_reason, side_peer="mac")
        if side == "android" and state.android_sockets.get(owner) is connection:
            state.android_sockets.pop(owner, None)
            diag("ws.close", link_id=owner, reason=close_reason, side_peer="android")
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


def attachment_path(value) -> str | None:
    if not isinstance(value, str):
        return None
    folder = next((prefix for prefix in ATTACHMENT_PREFIXES if value.startswith(prefix)), None)
    if folder is None:
        return None
    name = value[len(folder):]
    if not safe_file_name(name):
        return None
    return value


def safe_file_name(name: str) -> bool:
    return (
        bool(name)
        and len(name) <= 255
        and "/" not in name
        and "\\" not in name
        and "\0" not in name
        and name not in {".", ".."}
    )


async def begin_project_file(state: RelayState, connection: Connection, message: dict) -> None:
    request_id = str(message.get("request_id") or "")

    def reject(text: str) -> dict:
        return {"op": "error", "code": "bad_action", "request_id": request_id, "message": text}

    if set(message) - PROJECT_FILE_FIELDS:
        await connection.send(reject("不能指定保存位置"))
        return
    hold = message.get("hold", False)
    if hold is not False and hold is not True:
        await connection.send(reject("无法保存这个文件"))
        return
    name = message.get("name")
    kind = message.get("kind")
    profile = message.get("profile", "")
    project_id = message.get("project_id", "")
    size = file_size(message.get("size"))
    if (
        not request_id
        or len(request_id) > 80
        or not isinstance(name, str)
        or not safe_file_name(name)
        or kind not in {"image", "file"}
        or not isinstance(profile, str)
        or (profile and PROFILE_RE.fullmatch(profile) is None)
        or not isinstance(project_id, str)
        or PROJECT_RE.fullmatch(project_id) is None
        or size is None
        or not 0 < size <= FILE_LIMIT
    ):
        await connection.send(reject("无法保存这个文件"))
        return
    if connection.pending_file is not None:
        await connection.send(reject("上一个文件还没传完"))
        return
    link_id = connection.owner
    link = state.links.get(link_id)
    if link is None:
        await connection.send({"op": "error", "code": "unknown_link", "request_id": request_id, "message": "关联不存在"})
        return
    if state.mac_sockets.get(link["device_id"]) is None:
        diag("forward.mac_offline", link_id=link_id, device_id=link["device_id"], request_id=request_id, kind="project_file_inbound", reason="missing_socket")
        await connection.send({"op": "error", "code": "mac_offline", "request_id": request_id, "message": "Mac 不在线"})
        return
    connection.pending_file = {
        "size": size,
        "message_id": request_id,
        "forward": {
            "op": "project_file_inbound",
            "link_id": link_id,
            "request_id": request_id,
            "name": name,
            "size": size,
            "kind": kind,
            "profile": profile,
            "project_id": project_id,
            "peer": "mac",
            "peer_id": link["device_id"],
        },
    }
    if hold:
        connection.pending_file["forward"]["hold"] = True


def held_id(value) -> str | None:
    if isinstance(value, str) and HOLD_RE.fullmatch(value):
        return value
    return None


async def begin_held_file(state: RelayState, connection: Connection, message: dict, placing: bool) -> None:
    request_id = str(message.get("request_id") or "")

    def reject(text: str) -> dict:
        return {"op": "error", "code": "bad_action", "request_id": request_id, "message": text}

    if set(message) - (PLACE_FIELDS if placing else DROP_FIELDS):
        await connection.send(reject("不能指定保存位置"))
        return
    ident = held_id(message.get("hold_id"))
    profile = message.get("profile", "")
    project_id = message.get("project_id", "")
    if (
        not request_id
        or len(request_id) > 80
        or ident is None
        or (
            placing
            and (
                not isinstance(profile, str)
                or (profile and PROFILE_RE.fullmatch(profile) is None)
                or not isinstance(project_id, str)
                or PROJECT_RE.fullmatch(project_id) is None
            )
        )
    ):
        await connection.send(reject("无法保存这个文件"))
        return
    link_id = connection.owner
    link = state.links.get(link_id)
    if link is None:
        await connection.send({"op": "error", "code": "unknown_link", "request_id": request_id, "message": "关联不存在"})
        return
    peer = state.mac_sockets.get(link["device_id"])
    if peer is None:
        diag("forward.mac_offline", link_id=link_id, device_id=link["device_id"], request_id=request_id, kind="project_file", reason="missing_socket")
        await connection.send({"op": "error", "code": "mac_offline", "request_id": request_id, "message": "Mac 不在线"})
        return
    payload = {
        "op": "project_file_place" if placing else "project_file_drop",
        "link_id": link_id,
        "request_id": request_id,
        "hold_id": ident,
    }
    if placing:
        payload["profile"] = profile
        payload["project_id"] = project_id
    try:
        await peer.send(payload)
    except Exception:
        state.mac_sockets.pop(link["device_id"], None)
        diag("forward.mac_offline", link_id=link_id, device_id=link["device_id"], request_id=request_id, kind="project_file", reason="send_failed")
        await connection.send({"op": "error", "code": "mac_offline", "request_id": request_id, "message": "Mac 不在线"})


async def forward_project_file_result(state: RelayState, connection: Connection, message: dict, link_id: str, request_id: str) -> None:
    link = state.links.get(link_id)
    if link is None or link["device_id"] != connection.owner:
        await connection.send({"op": "error", "code": "forbidden", "request_id": request_id, "message": "不能回复别人的关联"})
        return
    text = message.get("text")
    if not isinstance(text, str):
        text = ""
    if len(text) > 500:
        text = text[:500]
    ok = bool(message.get("ok"))
    dropped = message.get("dropped") is True
    ident = held_id(message.get("hold_id")) if ok and not dropped else None
    raw_path = message.get("path")
    path = attachment_path(raw_path) if ok and not dropped else None
    if ok and dropped:
        if raw_path not in {None, ""} or message.get("hold_id") not in {None, ""}:
            ok = False
            dropped = False
            text = "路径无效"
    elif ok and ident is not None and path is not None:
        pass
    elif ok and ident is not None:
        if raw_path not in {None, ""}:
            ok = False
            ident = None
            text = "路径无效"
    elif ok and path is not None and message.get("hold_id") in {None, ""}:
        pass
    elif ok:
        ok = False
        path = None
        ident = None
        text = "路径无效"
    peer = state.android_sockets.get(link_id)
    if peer is None:
        return
    payload = {
        "op": "project_file_result",
        "link_id": link_id,
        "request_id": request_id,
        "ok": ok,
        "text": text,
    }
    if ok and path is not None:
        payload["path"] = path
    if ok and ident is not None:
        payload["hold_id"] = ident
    if ok and dropped:
        payload["dropped"] = True
    try:
        await peer.send(payload)
    except Exception:
        state.android_sockets.pop(link_id, None)
        diag("peer_send_fail", link_id=link_id, device_id=link["device_id"], request_id=request_id, kind="project_file_result", side_peer="android")


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
            diag("forward.mac_offline", link_id=link_id, device_id=link["device_id"], request_id=message_id, kind="file", reason="missing_socket")
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
            diag("forward.android_offline", link_id=link_id, device_id=link["device_id"], request_id=message_id, kind="file_reply", reason="missing_socket")
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
            "request_id": pending["message_id"],
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
            diag(
                "forward.mac_offline",
                link_id=forward.get("link_id", ""),
                device_id=forward["peer_id"],
                request_id=pending["message_id"],
                kind="file_bytes",
                reason="send_failed",
            )
        else:
            state.android_sockets.pop(forward["peer_id"], None)
            code, message = "android_offline", "安卓不在线"
            diag(
                "forward.android_offline",
                link_id=forward.get("link_id", ""),
                request_id=pending["message_id"],
                kind="file_bytes",
                reason="send_failed",
            )
        await connection.send({
            "op": "error",
            "code": code,
            "message_id": pending["message_id"],
            "request_id": pending["message_id"],
            "message": message,
        })
        return
    await connection.send({
        "op": "accepted",
        "message_id": pending["message_id"],
        "request_id": pending["message_id"],
    })


def command_target_error(message: dict) -> str | None:
    action = str(message.get("action") or "")
    target = message.get("target")
    if action == "remote-press":
        if not isinstance(target, dict) or set(target) != {"button_id"}:
            return "bad_action"
        button_id = target.get("button_id")
        if (
            not isinstance(button_id, str)
            or not button_id.strip()
            or len(button_id) > 80
            or any(ch.isspace() for ch in button_id)
        ):
            return "bad_action"
        return None
    if action != "desktop-switch":
        return "bad_action" if "target" in message else None
    if not isinstance(target, dict) or set(target) - {"display_id", "space_id", "window_id", "pid"}:
        return "bad_action"
    display_id = target.get("display_id")
    space_id = target.get("space_id")
    window_id = target.get("window_id", 0)
    pid = target.get("pid", 0)
    if not isinstance(display_id, str) or not display_id.strip() or len(display_id) > 128:
        return "bad_action"
    if isinstance(space_id, bool) or not isinstance(space_id, int) or space_id < 0:
        return "bad_action"
    if isinstance(window_id, bool) or not isinstance(window_id, int) or window_id < 0:
        return "bad_action"
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0 or pid > 2**31 - 1:
        return "bad_action"
    if (window_id == 0) != (pid == 0):
        return "bad_action"
    return None


def app_request_error(message: dict) -> str | None:
    if set(message) - APP_FIELDS:
        return "bad_action"
    kind = str(message.get("kind") or "")
    if kind not in APP_KINDS or not str(message.get("request_id") or ""):
        return "bad_action"
    session_id = message.get("session_id", "")
    title = message.get("title", "")
    text = message.get("text", "")
    profile = message.get("profile", "")
    project_id = message.get("project_id", "")
    if not isinstance(session_id, str) or not isinstance(title, str) or not isinstance(text, str):
        return "bad_action"
    if not isinstance(profile, str) or not isinstance(project_id, str):
        return "bad_action"
    if len(session_id) > 256 or len(title) > 80 or len(text) > TEXT_LIMIT:
        return "bad_action"
    if any(char in session_id for char in "\r\n\x00/\\"):
        return "bad_action"
    if profile and PROFILE_RE.fullmatch(profile) is None:
        return "bad_action"
    if project_id and PROJECT_RE.fullmatch(project_id) is None:
        return "bad_action"
    path = message.get("path", "")
    if not valid_home_path(path) or (path and kind not in PATH_KINDS):
        return "bad_action"
    if "offset" in message:
        offset = message.get("offset")
        if kind not in {"preview", "tree"} or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or offset > 5_000_000:
            return "bad_action"
    if "cursor" in message:
        cursor = message.get("cursor")
        if kind != "messages" or not isinstance(cursor, str) or CURSOR_RE.fullmatch(cursor) is None:
            return "bad_action"
        if cursor.startswith("older:") and int(cursor.split(":", 1)[1]) <= 0:
            return "bad_action"
    if kind == "model_select":
        if MODEL_RE.fullmatch(text) is None or PROVIDER_RE.fullmatch(title) is None:
            return "bad_action"
        if session_id or project_id or path:
            return "bad_action"
    if kind == "models":
        if text or title or session_id or project_id or path:
            return "bad_action"
    return None


def valid_home_path(path: object) -> bool:
    if not isinstance(path, str) or len(path) > PATH_LIMIT:
        return False
    if path == "":
        return True
    if path.startswith("/") or any(ord(char) < 32 or ord(char) == 127 for char in path):
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/"))


async def forward_app(state: RelayState, connection: Connection, message: dict, request_id: str) -> None:
    if app_request_error(message):
        await connection.send({"op": "error", "code": "bad_action", "request_id": request_id, "message": "动作不在白名单"})
        return
    link = state.links.get(connection.owner)
    if link is None:
        await connection.send({"op": "error", "code": "unknown_link", "request_id": request_id, "message": "关联不存在"})
        return
    kind = str(message.get("kind") or "")
    peer = state.mac_sockets.get(link["device_id"])
    if peer is None:
        diag("forward.mac_offline", link_id=connection.owner, device_id=link["device_id"], request_id=request_id, kind=kind, reason="missing_socket")
        await connection.send({"op": "error", "code": "mac_offline", "request_id": request_id, "message": "Mac 不在线"})
        return
    forwarded = {
        "op": "app_inbound",
        "link_id": connection.owner,
        "request_id": request_id,
        "kind": message.get("kind"),
        "session_id": message.get("session_id", ""),
        "title": message.get("title", ""),
        "text": message.get("text", ""),
        "profile": message.get("profile", ""),
        "project_id": message.get("project_id", ""),
    }
    if forwarded["kind"] in PATH_KINDS:
        forwarded["path"] = message.get("path", "")
    if forwarded["kind"] in {"preview", "tree"}:
        forwarded["offset"] = message.get("offset", 0)
    if forwarded["kind"] == "messages" and message.get("cursor"):
        forwarded["cursor"] = message["cursor"]
    diag(
        "app.forward",
        link_id=connection.owner,
        device_id=link["device_id"],
        request_id=request_id,
        kind=kind,
        has_path=bool(forwarded.get("path")),
    )
    try:
        await peer.send(forwarded)
    except Exception:
        state.mac_sockets.pop(link["device_id"], None)
        diag("forward.mac_offline", link_id=connection.owner, device_id=link["device_id"], request_id=request_id, kind=kind, reason="send_failed")
        await connection.send({"op": "error", "code": "mac_offline", "request_id": request_id, "message": "Mac 不在线"})
        return
    await connection.send({"op": "accepted", "request_id": request_id})


async def forward_app_result(state: RelayState, connection: Connection, message: dict, link_id: str, request_id: str) -> None:
    allowed = {"op", "link_id", "request_id", "ok", "text", "kind", "body"}
    if set(message) - allowed:
        await connection.send({"op": "error", "code": "bad_action", "request_id": request_id, "message": "动作不在白名单"})
        return
    link = state.links.get(link_id)
    if link is None or link["device_id"] != connection.owner:
        await connection.send({"op": "error", "code": "forbidden", "request_id": request_id, "message": "不能回复别人的关联"})
        return
    text = message.get("text") if isinstance(message.get("text"), str) else ""
    body = message.get("body") if isinstance(message.get("body"), dict) else {}
    payload = {
        "op": "app_result",
        "link_id": link_id,
        "request_id": request_id,
        "kind": str(message.get("kind") or ""),
        "ok": bool(message.get("ok")),
        "text": text[:TEXT_LIMIT],
        "body": body,
    }
    encoded = json.dumps(payload, ensure_ascii=False)
    limit = PREVIEW_RESULT_LIMIT if payload["kind"] in {"preview", "tree"} else APP_RESULT_LIMIT
    if len(encoded) > limit:
        payload["body"] = {}
        payload["text"] = "内容太长"
        payload["ok"] = False
    peer = state.android_sockets.get(link_id)
    if peer is None:
        diag("forward.android_offline", link_id=link_id, device_id=connection.owner, request_id=request_id, kind=payload.get("kind", ""), reason="missing_socket")
        return
    try:
        await peer.send(payload)
    except Exception:
        state.android_sockets.pop(link_id, None)
        diag("peer_send_fail", link_id=link_id, device_id=connection.owner, request_id=request_id, kind=payload.get("kind", ""), side_peer="android")


async def notify_revoked(state: RelayState, link: dict) -> None:
    diag("link.revoked", link_id=link.get("id", ""), device_id=link.get("device_id", ""))
    payload = {"op": "link_revoked", "link_id": link["id"]}
    android = state.android_sockets.pop(link["id"], None)
    if android is not None:
        try:
            await android.send(payload)
        except Exception:
            pass
        android.writer.close()
    mac = state.mac_sockets.get(link["device_id"])
    if mac is not None:
        try:
            await mac.send(payload)
        except Exception:
            state.mac_sockets.pop(link["device_id"], None)


async def on_text(state: RelayState, connection: Connection, raw: str) -> None:
    message = json.loads(raw)
    if any(key in message for key in FORBIDDEN_FIELDS):
        await connection.send({"op": "error", "code": "forbidden_field", "message": "不能携带密钥或提示词"})
        return
    op = message.get("op")
    link_id = str(message.get("link_id") or "")
    request_id = str(message.get("request_id") or "")
    if connection.side == "android" and op == "command":
        link_id = connection.owner
        action = str(message.get("action") or "")
        if action not in ACTIONS or not request_id or command_target_error(message):
            await connection.send({"op": "error", "code": "bad_action", "request_id": request_id, "message": "动作不在白名单"})
            return
        link = state.links.get(link_id)
        if link is None:
            await connection.send({"op": "error", "code": "unknown_link", "request_id": request_id, "message": "关联不存在"})
            return
        peer = state.mac_sockets.get(link["device_id"])
        if peer is None:
            diag("forward.mac_offline", link_id=link_id, device_id=link["device_id"], request_id=request_id, kind=action, reason="missing_socket")
            await connection.send({"op": "error", "code": "mac_offline", "request_id": request_id, "message": "Mac 不在线"})
            return
        try:
            forwarded = {
                "op": "command_inbound",
                "link_id": link_id,
                "request_id": request_id,
                "action": action,
                "android_id": link["android_id"],
            }
            if action == "desktop-switch":
                target = message["target"]
                forwarded["target"] = {
                    "display_id": target["display_id"],
                    "space_id": target["space_id"],
                    "window_id": target.get("window_id", 0),
                    "pid": target.get("pid", 0),
                }
            elif action == "remote-press":
                forwarded["target"] = {"button_id": message["target"]["button_id"]}
            await peer.send(forwarded)
        except Exception:
            state.mac_sockets.pop(link["device_id"], None)
            diag("forward.mac_offline", link_id=link_id, device_id=link["device_id"], request_id=request_id, kind=action, reason="send_failed")
            await connection.send({"op": "error", "code": "mac_offline", "request_id": request_id, "message": "Mac 不在线"})
            return
        await connection.send({"op": "accepted", "request_id": request_id})
        return
    if connection.side == "android" and op == "app":
        await forward_app(state, connection, message, request_id)
        return
    if connection.side == "android" and op == "project_file":
        await begin_project_file(state, connection, message)
        return
    if connection.side == "android" and op == "project_file_place":
        await begin_held_file(state, connection, message, placing=True)
        return
    if connection.side == "android" and op == "project_file_drop":
        await begin_held_file(state, connection, message, placing=False)
        return
    if connection.side == "mac" and op == "app_result":
        await forward_app_result(state, connection, message, link_id, request_id)
        return
    if connection.side == "mac" and op == "project_file_result":
        await forward_project_file_result(state, connection, message, link_id, request_id)
        return
    if connection.side == "mac" and op == "result":
        link = state.links.get(link_id)
        if link is None or link["device_id"] != connection.owner:
            await connection.send({"op": "error", "code": "forbidden", "request_id": request_id, "message": "不能回复别人的关联"})
            return
        text = message.get("text")
        if not isinstance(text, str):
            text = ""
        peer = state.android_sockets.get(link_id)
        if peer is None:
            return
        payload = {
            "op": "result",
            "link_id": link_id,
            "request_id": request_id,
            "ok": bool(message.get("ok")),
            "text": text,
        }
        body = message.get("body")
        if isinstance(body, dict):
            encoded = json.dumps(body, ensure_ascii=False)
            if len(encoded) <= PREVIEW_RESULT_LIMIT:
                payload["body"] = body
        try:
            await peer.send(payload)
        except Exception:
            state.android_sockets.pop(link_id, None)
        return
    await connection.send({"op": "error", "code": "bad_op", "request_id": request_id, "message": "无法处理"})


async def handle(reader, writer, state: RelayState) -> None:
    try:
        await dispatch(reader, writer, state)
    except Exception:
        try:
            writer.close()
        except Exception:
            pass


async def serve(host: str, port: int, data_path: str | None, cert: str, key: str, diag_dir: str | None = None) -> None:
    configure_diag(diag_dir)
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
    diag("relay.start", host=str(bound[0]), port=int(bound[1]))
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
    parser.add_argument("--diag", default="", help="诊断 JSONL 目录，默认 diagnostics 或 TOCODE_DIAG_DIR")
    args = parser.parse_args()
    asyncio.run(serve(args.host, args.port, args.data or None, args.cert, args.key, args.diag or None))


if __name__ == "__main__":
    main()
