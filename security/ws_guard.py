"""WebSocket security guard for the collaborative whiteboard.

Centralises every handshake / connection / frame-level control so that the
transport layer cannot silently skip one of them:

1.  Origin allow-list (CSWSH / cross-site WebSocket hijacking).
2.  Tokens are accepted from headers only, never from the URL query string
    (query strings land in proxy / access logs).
3.  Sec-WebSocket-Protocol allow-list.
4.  Per-room authorisation (constant-time token comparison).
5.  Room-isolated broadcast via :class:`RoomRegistry`.
6.  Per-frame size cap.
7.  Token-bucket rate limiting via :class:`TokenBucket` / :class:`MessageGate`.
8.  Reconnect is treated as a brand-new handshake, fully re-authenticated.
9.  Uniform private close codes (4000-4099), no internal reason leak.
10. Binary frames rejected; only validated text (JSON) frames accepted.
11. Permessage-deflate refused, compressed frames rejected (compression
    side-channel / BREACH-style oracle).
12. Server-side ping/pong heartbeat so idle connections are not reaped by
    intermediaries.

The module only depends on the standard library.
"""

from __future__ import annotations

import hmac
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Optional
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Close codes (RFC 6455 reserves 4000-4099 for application/private use).
# ---------------------------------------------------------------------------
CLOSE_INTERNAL = 4000        # generic failure, no internal detail leaked
CLOSE_AUTH = 4001            # authentication failed / expired / reconnect
CLOSE_ORIGIN = 4002          # Origin not on the allow-list
CLOSE_SUBPROTOCOL = 4003     # negotiated sub-protocol not allowed
CLOSE_ROOM = 4004            # not authorised for the requested room
CLOSE_POLICY = 4005          # frame policy violation (binary / compressed)
CLOSE_TOO_LARGE = 4006       # frame exceeded the size cap
CLOSE_RATE_LIMIT = 4007      # message rate exceeded
CLOSE_HEARTBEAT = 4008       # peer failed the ping/pong heartbeat
CLOSE_URL_TOKEN = 4009       # token presented in the URL query string

_CLOSE_BY_REASON = {
    'internal': CLOSE_INTERNAL,
    'auth': CLOSE_AUTH,
    'origin': CLOSE_ORIGIN,
    'subprotocol': CLOSE_SUBPROTOCOL,
    'room': CLOSE_ROOM,
    'policy': CLOSE_POLICY,
    'too_large': CLOSE_TOO_LARGE,
    'rate_limit': CLOSE_RATE_LIMIT,
    'heartbeat': CLOSE_HEARTBEAT,
    'url_token': CLOSE_URL_TOKEN,
}

# ---------------------------------------------------------------------------
# Tunable defaults.
# ---------------------------------------------------------------------------
DEFAULT_MAX_FRAME_BYTES = 1 << 20   # 1 MiB hard cap for a single frame
DEFAULT_RATE_LIMIT = 20             # messages ...
DEFAULT_RATE_WINDOW = 1.0           # ... per second, per connection
PING_INTERVAL_SECONDS = 30.0        # server pings on this cadence
PONG_TIMEOUT_SECONDS = 10.0         # ... and gives up after this long

_VALID_OPCODES = frozenset({'text', 'binary', 'ping', 'pong', 'close'})
_VALID_SCHEMES = frozenset(('http', 'https', 'ws', 'wss'))
# RFC 6455 Sec-WebSocket-Protocol token: 1*<visible ascii excluding separators>
_SUBPROTO_FORBIDDEN = frozenset('()<>@,;:\\"/[]?={} \t')


# ---------------------------------------------------------------------------
# 1. Origin allow-list
# ---------------------------------------------------------------------------
def _origin_parts(origin: str) -> Optional[tuple]:
    """Split an Origin into its (scheme, host, port) tuple.

    Returns ``None`` for anything that is not a valid, precisely-specified
    Origin.  Query strings and fragments are illegal here, which is also what
    keeps bearer tokens out of the URL.
    """
    if not isinstance(origin, str) or not origin:
        return None
    parts = urlsplit(origin)
    if parts.query or parts.fragment:
        return None
    if parts.scheme not in _VALID_SCHEMES or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if parts.path and parts.path != '/':
        return None
    # Explicit default port stays part of the exact match; absence is a
    # different key so the allow-list stays explicit and auditable.
    return (parts.scheme, parts.hostname, parts.port)


def origin_allowed(origin: object, allowed: Iterable[str]) -> bool:
    """Exact-match *origin* against an allow-list.

    No suffix matching, no wildcard: ``https://app.example.evil`` must never
    match ``https://app.example``.  Origins carrying a query string (e.g.
    ``https://app.example?token=x``) are rejected outright.
    """
    wanted = _origin_parts(origin) if isinstance(origin, str) else None
    if wanted is None:
        return False
    try:
        allow_list = frozenset(allowed)
    except TypeError:
        return False
    for entry in allow_list:
        entry_parts = _origin_parts(entry)
        if entry_parts is not None and entry_parts == wanted:
            return True
    return False


# ---------------------------------------------------------------------------
# 2. Token must not travel in the URL
# ---------------------------------------------------------------------------
_TOKEN_QUERY_KEYS = frozenset(('token', 'access_token', 'auth', 'jwt'))


def url_has_token(url: str) -> bool:
    """True if the URL query string tries to carry an auth token."""
    try:
        query = urlsplit(url).query
    except (ValueError, AttributeError):
        return True
    if not query:
        return False
    for pair in query.split('&'):
        key = pair.split('=', 1)[0].lower()
        if key in _TOKEN_QUERY_KEYS:
            return True
    return False


def extract_token(headers: Mapping[str, str]) -> Optional[str]:
    """Read the bearer token from request headers only.

    Supports the standard ``Authorization: Bearer <token>`` header and an
    equivalent ``Sec-WebSocket-Protocol``-independent ``X-Auth-Token``
    header.  The URL is deliberately never consulted.
    """
    if not isinstance(headers, Mapping):
        return None
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        if name.lower() == 'authorization':
            scheme, _, bearer = value.partition(' ')
            if scheme.lower() == 'bearer' and bearer.strip():
                return bearer.strip()
    token = headers.get('X-Auth-Token')
    if isinstance(token, str) and token.strip():
        return token.strip()
    return None


# ---------------------------------------------------------------------------
# 3. Sec-WebSocket-Protocol allow-list
# ---------------------------------------------------------------------------
def subprotocol_allowed(protocol: object, allowed: Iterable[str]) -> bool:
    """Exact-match the negotiated sub-protocol against an allow-list."""
    if not isinstance(protocol, str) or not protocol:
        return False
    if any(ch in _SUBPROTO_FORBIDDEN or ord(ch) < 0x21 or ord(ch) > 0x7E
           for ch in protocol):
        return False
    try:
        return protocol in frozenset(allowed)
    except TypeError:
        return False


# ---------------------------------------------------------------------------
# 4. Room-level authorisation
# ---------------------------------------------------------------------------
def room_allowed(room: object, user_token: object, room_token: object) -> bool:
    """Authorise *user_token* for *room* against the room's bound token.

    Comparison is constant-time to avoid leaking the room token through
    timing.  Any missing or non-string argument denies the request.
    """
    if not all(isinstance(v, str) for v in (room, user_token, room_token)):
        return False
    if not room or not user_token or not room_token:
        return False
    return hmac.compare_digest(user_token, room_token)


# ---------------------------------------------------------------------------
# 5/6/10/11. Frame policy: size cap, no binary, no compression
# ---------------------------------------------------------------------------
def frame_ok(size: object,
             max_size: object,
             *,
             binary: bool = False,
             compressed: bool = False,
             opcode: str = 'text') -> bool:
    """Validate one inbound frame against connection policy.

    * Binary frames are rejected: the whiteboard protocol is JSON text only,
      so a binary frame cannot be JSON-validated and must not bypass it.
    * Compressed frames are rejected: permessage-deflate is not negotiated,
      and compression opens a size/oracle side-channel.
    * Data frames must fit inside *max_size*.
    * Control frames (ping/pong/close) are always small per RFC 6455 and are
      exempt from the application size cap -- heartbeats must still flow.
    """
    if isinstance(binary, str) or isinstance(compressed, str):
        return False
    if opcode not in _VALID_OPCODES:
        return False
    if binary or opcode == 'binary':
        return False
    if compressed:
        return False
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return False
    if opcode in ('ping', 'pong', 'close'):
        return True
    if not isinstance(max_size, int) or isinstance(max_size, bool) \
            or max_size < 0:
        return False
    return size <= max_size


# ---------------------------------------------------------------------------
# 7. Rate limiting (token bucket)
# ---------------------------------------------------------------------------
class TokenBucket:
    """Thread-safe token bucket: at most ``rate`` events per ``window``."""

    def __init__(self, rate: int, window: float = DEFAULT_RATE_WINDOW,
                 *, clock: Callable[[], float] = time.monotonic):
        if rate <= 0 or window <= 0:
            raise ValueError('rate and window must be positive')
        self._capacity = float(rate)
        self._refill_per_second = float(rate) / float(window)
        self._tokens = float(rate)
        self._clock = clock
        self._updated = clock()
        self._lock = threading.Lock()

    def allow(self, cost: float = 1.0) -> bool:
        if cost <= 0:
            raise ValueError('cost must be positive')
        with self._lock:
            now = self._clock()
            elapsed = max(0.0, now - self._updated)
            self._tokens = min(
                self._capacity,
                self._tokens + elapsed * self._refill_per_second)
            self._updated = now
            if self._tokens >= cost:
                self._tokens -= cost
                return True
            return False


# ---------------------------------------------------------------------------
# 5. Room-isolated broadcast registry
# ---------------------------------------------------------------------------
@dataclass
class RoomRegistry:
    """Tracks connections per room and enforces broadcast isolation.

    A message accepted in room A can only ever be delivered to connections
    joined to room A; there is no global fan-out path.
    """

    _rooms: dict = field(default_factory=dict, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock,
                                   init=False, repr=False)

    def join(self, room: str, connection: object,
             user_token: str, room_token: str) -> bool:
        """Join *room* after re-checking room authorisation."""
        if not room_allowed(room, user_token, room_token):
            return False
        with self._lock:
            self._rooms.setdefault(room, set()).add(connection)
        return True

    def leave(self, room: str, connection: object) -> None:
        with self._lock:
            members = self._rooms.get(room)
            if members is not None:
                members.discard(connection)
                if not members:
                    del self._rooms[room]

    def members(self, room: str) -> frozenset:
        with self._lock:
            return frozenset(self._rooms.get(room, ()))

    def broadcast(self, room: str, sender: object, payload: object,
                  send: Callable[[object, object], None]) -> int:
        """Deliver *payload* only to other members of *room*.

        Returns the number of deliveries.  A failing peer never aborts the
        fan-out to the rest of the room.
        """
        delivered = 0
        for peer in self.members(room):
            if peer is sender:
                continue
            try:
                send(peer, payload)
            except Exception:
                # A dead socket must not block delivery to healthy peers.
                continue
            delivered += 1
        return delivered


# ---------------------------------------------------------------------------
# 7+6. Per-connection gate combining frame policy and rate limiting
# ---------------------------------------------------------------------------
class MessageGate:
    """One gate per live connection: frame policy first, then rate limit."""

    def __init__(self, max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
                 rate: int = DEFAULT_RATE_LIMIT,
                 window: float = DEFAULT_RATE_WINDOW,
                 *, clock: Optional[Callable[[], float]] = None):
        self.max_frame_bytes = max_frame_bytes
        clock = clock or time.monotonic
        self._bucket = TokenBucket(rate, window, clock=clock)

    def check(self, size: int, *, binary: bool = False,
              compressed: bool = False, opcode: str = 'text') -> int:
        """Return the close code to send, or ``0`` when the frame is accepted."""
        if opcode in ('ping', 'pong', 'close'):
            # Control traffic is never application data and never billed.
            return 0 if frame_ok(size, self.max_frame_bytes,
                                 binary=binary, compressed=compressed,
                                 opcode=opcode) else CLOSE_POLICY
        if not frame_ok(size, self.max_frame_bytes, binary=binary,
                        compressed=compressed, opcode=opcode):
            if binary or compressed or opcode == 'binary':
                return CLOSE_POLICY
            return CLOSE_TOO_LARGE
        if not self._bucket.allow():
            return CLOSE_RATE_LIMIT
        return 0


# ---------------------------------------------------------------------------
# 8. Reconnect always re-authenticates (full handshake)
# ---------------------------------------------------------------------------
def authorize_handshake(*,
                        origin: str,
                        allowed_origins: Iterable[str],
                        headers: Mapping[str, str],
                        url: str,
                        subprotocol: Optional[str],
                        allowed_subprotocols: Iterable[str],
                        room: str,
                        room_token: str) -> tuple:
    """Run every handshake check in order; invoked on *every* connection.

    A reconnect has no cached state and passes through the exact same checks
    as the first connection.  Returns ``(ok, close_code, selected_protocol,
    token)``.
    """
    if url_has_token(url):
        return False, CLOSE_URL_TOKEN, None, None
    if not origin_allowed(origin, allowed_origins):
        return False, CLOSE_ORIGIN, None, None
    token = extract_token(headers)
    if token is None:
        return False, CLOSE_AUTH, None, None
    if not subprotocol_allowed(subprotocol, allowed_subprotocols):
        return False, CLOSE_SUBPROTOCOL, None, None
    if not room_allowed(room, token, room_token):
        return False, CLOSE_ROOM, None, None
    return True, 0, subprotocol, token


# ---------------------------------------------------------------------------
# 9. Uniform close codes
# ---------------------------------------------------------------------------
def close_code(reason: object) -> int:
    """Map an internal *reason* to a generic application close code.

    Unknown reasons collapse to :data:`CLOSE_INTERNAL` so exception text and
    internal identifiers never reach the client.
    """
    if not isinstance(reason, str):
        return CLOSE_INTERNAL
    return _CLOSE_BY_REASON.get(reason, CLOSE_INTERNAL)


# ---------------------------------------------------------------------------
# 12. Server-side heartbeat
# ---------------------------------------------------------------------------
@dataclass
class Heartbeat:
    """Tracks ping/pong liveness for one connection."""

    interval: float = PING_INTERVAL_SECONDS
    timeout: float = PONG_TIMEOUT_SECONDS
    _last_ping: Optional[float] = field(default=None, init=False)
    _last_pong: float = field(default=0.0, init=False)
    _awaiting_pong: bool = field(default=False, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock,
                                  init=False, repr=False)

    def should_ping(self, now: float) -> bool:
        with self._lock:
            if self._awaiting_pong:
                return False
            if self._last_ping is None:
                return True
            return now - self._last_ping >= self.interval

    def ping_sent(self, now: float) -> None:
        with self._lock:
            self._last_ping = now
            self._awaiting_pong = True

    def pong_received(self, now: float) -> None:
        with self._lock:
            self._last_pong = now
            self._awaiting_pong = False

    def is_dead(self, now: float) -> bool:
        """True when a pong is outstanding past the timeout."""
        with self._lock:
            return (self._awaiting_pong
                    and self._last_ping is not None
                    and now - self._last_ping > self.timeout)
