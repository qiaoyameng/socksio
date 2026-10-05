import typing

import pytest

from socksio import (
    ProtocolError,
    SOCKS5AType,
    SOCKS5AuthMethod,
    SOCKS5AuthMethodsRequest,
    SOCKS5AuthReply,
    SOCKS5Command,
    SOCKS5CommandRequest,
    SOCKS5Connection,
    SOCKS5GSSAPIProtectionLevel,
    SOCKS5GSSAPIProtectionReply,
    SOCKS5GSSAPIProtectionRequest,
    SOCKS5GSSAPIReply,
    SOCKS5GSSAPIRequest,
    SOCKS5Reply,
    SOCKS5ReplyCode,
)
from socksio.socks5 import SOCKS5State


class FakeGSSAPIError(Exception):
    """Raised by the fake context when a record fails verification."""


class FakeGSSAPIContext:
    """A fake GSSAPI context with inspectable call counts.

    ``wrap`` prepends a one-byte checksum tag that ``unwrap`` verifies,
    emulating integrity protection without any Kerberos dependency.
    """

    def __init__(self, steps_to_complete: int = 2) -> None:
        self.steps_to_complete = steps_to_complete
        self.step_calls = 0
        self.wrap_calls = 0
        self.unwrap_calls = 0
        self.stepped_tokens: typing.List[bytes] = []
        self.unwrapped_data: typing.List[bytes] = []

    @property
    def complete(self) -> bool:
        return self.step_calls >= self.steps_to_complete

    def step(self, token: bytes) -> bytes:
        self.step_calls += 1
        self.stepped_tokens.append(token)
        return f"client-token-{self.step_calls}".encode()

    def wrap(self, data: bytes) -> bytes:
        self.wrap_calls += 1
        return bytes([sum(data) % 256]) + data

    def unwrap(self, data: bytes) -> bytes:
        self.unwrap_calls += 1
        tag, body = data[0], data[1:]
        if sum(body) % 256 != tag:
            raise FakeGSSAPIError("invalid authentication tag")
        self.unwrapped_data.append(body)
        return body


def token_message(token: bytes) -> bytes:
    """Builds a GSSAPI authentication message (MTYP=1) carrying a token."""
    return b"\x01\x01" + len(token).to_bytes(2, byteorder="big") + token


def protection_reply_message(level: SOCKS5GSSAPIProtectionLevel) -> bytes:
    return b"\x01\x02\x00\x01" + bytes([level])


def protected_record(data: bytes) -> bytes:
    """Frames data the same way the fake server would: tag + length prefix."""
    token = bytes([sum(data) % 256]) + data
    return len(token).to_bytes(2, byteorder="big") + token


def feed_byte_by_byte(
    conn: SOCKS5Connection, record: bytes
) -> typing.List[typing.Any]:
    return [conn.receive_data(record[i : i + 1]) for i in range(len(record))]


def drive_gssapi_handshake(
    conn: SOCKS5Connection,
    server_protection: SOCKS5GSSAPIProtectionLevel = (
        SOCKS5GSSAPIProtectionLevel.INTEGRITY
    ),
) -> None:
    """Drives the connection through GSSAPI auth up to CLIENT_AUTHENTICATED."""
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]))
    conn.data_to_send()
    conn.receive_data(b"\x05" + SOCKS5AuthMethod.GSSAPI)
    while conn.state == SOCKS5State.SERVER_GSSAPI_TOKEN_REPLY:
        conn.data_to_send()
        conn.receive_data(token_message(b"server-token"))
    conn.data_to_send()
    conn.receive_data(protection_reply_message(server_protection))


@pytest.fixture
def gssapi_context() -> FakeGSSAPIContext:
    return FakeGSSAPIContext(steps_to_complete=1)


@pytest.fixture
def protected_conn(gssapi_context: FakeGSSAPIContext) -> SOCKS5Connection:
    conn = SOCKS5Connection(gssapi_context=gssapi_context)
    drive_gssapi_handshake(conn)
    return conn


@pytest.fixture
def tunnel_conn(protected_conn: SOCKS5Connection) -> SOCKS5Connection:
    cmd_request = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    )
    protected_conn.send(cmd_request)
    protected_conn.data_to_send()
    reply_data = b"\x05\x00\x00\x01\x7f\x00\x00\x01" + (1080).to_bytes(2, "big")
    protected_conn.receive_data(protected_record(reply_data))
    assert protected_conn.state == SOCKS5State.TUNNEL_READY
    return protected_conn


def test_gssapi_request_dumps() -> None:
    request = SOCKS5GSSAPIRequest(token=b"token")
    assert request.dumps() == b"\x01\x01\x00\x05token"


def test_gssapi_reply_loads() -> None:
    reply = SOCKS5GSSAPIReply.loads(b"\x01\x01\x00\x05token")
    assert reply == SOCKS5GSSAPIReply(token=b"token")


@pytest.mark.parametrize(
    "data",
    [
        b"\x01\x01\x00",  # too short for the header
        b"\x02\x01\x00\x00",  # unsupported version
        b"\x01\x02\x00\x00",  # unexpected message type
        b"\x01\x01\x00\x05ab",  # token shorter than announced
        b"\x01\x01\x00\x01ab",  # token longer than announced
    ],
)
def test_gssapi_reply_malformed(data: bytes) -> None:
    with pytest.raises(ProtocolError):
        SOCKS5GSSAPIReply.loads(data)


def test_gssapi_protection_request_dumps() -> None:
    request = SOCKS5GSSAPIProtectionRequest(protection_levels=0x03)
    assert request.dumps() == b"\x01\x02\x00\x01\x03"


def test_gssapi_protection_reply_loads() -> None:
    reply = SOCKS5GSSAPIProtectionReply.loads(b"\x01\x02\x00\x01\x02")
    assert reply == SOCKS5GSSAPIProtectionReply(
        protection_level=SOCKS5GSSAPIProtectionLevel.CONFIDENTIALITY
    )


@pytest.mark.parametrize(
    "data",
    [
        b"\x01\x02\x00\x01",  # missing token byte
        b"\x01\x02\x00\x01\x01\x00",  # trailing data
        b"\x02\x02\x00\x01\x01",  # unsupported version
        b"\x01\x01\x00\x01\x01",  # unexpected message type
        b"\x01\x02\x00\x02\x01",  # invalid length
        b"\x01\x02\x00\x01\x07",  # unknown protection level
    ],
)
def test_gssapi_protection_reply_malformed(data: bytes) -> None:
    with pytest.raises(ProtocolError):
        SOCKS5GSSAPIProtectionReply.loads(data)


def test_gssapi_selected_without_context_must_close() -> None:
    conn = SOCKS5Connection()
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]))
    conn.data_to_send()

    with pytest.raises(ProtocolError):
        conn.receive_data(b"\x05" + SOCKS5AuthMethod.GSSAPI)

    assert conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_multi_round_token_exchange() -> None:
    context = FakeGSSAPIContext(steps_to_complete=3)
    conn = SOCKS5Connection(gssapi_context=context)
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]))
    assert conn.data_to_send() == b"\x05\x01\x01"

    reply = conn.receive_data(b"\x05" + SOCKS5AuthMethod.GSSAPI)
    assert reply == SOCKS5AuthReply(method=SOCKS5AuthMethod.GSSAPI)
    assert conn.state == SOCKS5State.SERVER_GSSAPI_TOKEN_REPLY
    assert context.step_calls == 1
    assert context.stepped_tokens == [b""]
    assert conn.data_to_send() == token_message(b"client-token-1")

    reply = conn.receive_data(token_message(b"server-token-1"))
    assert reply == SOCKS5GSSAPIReply(token=b"server-token-1")
    assert conn.state == SOCKS5State.SERVER_GSSAPI_TOKEN_REPLY
    assert context.step_calls == 2
    assert context.stepped_tokens == [b"", b"server-token-1"]
    assert conn.data_to_send() == token_message(b"client-token-2")

    reply = conn.receive_data(token_message(b"server-token-2"))
    assert reply == SOCKS5GSSAPIReply(token=b"server-token-2")
    assert context.step_calls == 3
    assert context.complete
    assert conn.state == SOCKS5State.SERVER_GSSAPI_PROTECTION_REPLY
    # The final context token is flushed before the protection negotiation.
    assert conn.data_to_send() == token_message(b"client-token-3") + (
        b"\x01\x02\x00\x01\x03"
    )

    reply = conn.receive_data(b"\x01\x02\x00\x01\x01")
    assert reply == SOCKS5GSSAPIProtectionReply(
        protection_level=SOCKS5GSSAPIProtectionLevel.INTEGRITY
    )
    assert conn.state == SOCKS5State.CLIENT_AUTHENTICATED


def test_gssapi_empty_final_token_is_not_sent() -> None:
    class EmptyFinalTokenContext(FakeGSSAPIContext):
        def step(self, token: bytes) -> bytes:
            super().step(token)
            return b"" if self.complete else b"client-token"

    context = EmptyFinalTokenContext(steps_to_complete=1)
    conn = SOCKS5Connection(gssapi_context=context)
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]))
    conn.data_to_send()
    conn.receive_data(b"\x05" + SOCKS5AuthMethod.GSSAPI)

    assert conn.state == SOCKS5State.SERVER_GSSAPI_PROTECTION_REPLY
    assert conn.data_to_send() == b"\x01\x02\x00\x01\x03"


@pytest.mark.parametrize(
    "minimum,expected_mask",
    [
        (SOCKS5GSSAPIProtectionLevel.NONE, 0x03),
        (SOCKS5GSSAPIProtectionLevel.INTEGRITY, 0x03),
        (SOCKS5GSSAPIProtectionLevel.CONFIDENTIALITY, 0x02),
    ],
)
def test_gssapi_offered_protection_levels_respect_minimum(
    minimum: SOCKS5GSSAPIProtectionLevel, expected_mask: int
) -> None:
    context = FakeGSSAPIContext(steps_to_complete=1)
    conn = SOCKS5Connection(
        gssapi_context=context, minimum_gssapi_protection_level=minimum
    )
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]))
    conn.data_to_send()
    conn.receive_data(b"\x05" + SOCKS5AuthMethod.GSSAPI)

    assert conn.state == SOCKS5State.SERVER_GSSAPI_PROTECTION_REPLY
    sent = conn.data_to_send()
    assert sent.endswith(b"\x01\x02\x00\x01" + bytes([expected_mask]))


def test_gssapi_protection_below_minimum_is_rejected() -> None:
    context = FakeGSSAPIContext(steps_to_complete=1)
    conn = SOCKS5Connection(
        gssapi_context=context,
        minimum_gssapi_protection_level=SOCKS5GSSAPIProtectionLevel.CONFIDENTIALITY,
    )
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]))
    conn.data_to_send()
    conn.receive_data(b"\x05" + SOCKS5AuthMethod.GSSAPI)
    conn.data_to_send()

    with pytest.raises(ProtocolError):
        conn.receive_data(
            protection_reply_message(SOCKS5GSSAPIProtectionLevel.INTEGRITY)
        )

    assert conn.state == SOCKS5State.MUST_CLOSE
    # No fallback to a plaintext connection is possible after the failure.
    with pytest.raises(ProtocolError):
        conn.receive_data(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x04\x38")


def test_gssapi_malformed_token_reply_must_close() -> None:
    context = FakeGSSAPIContext(steps_to_complete=2)
    conn = SOCKS5Connection(gssapi_context=context)
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]))
    conn.data_to_send()
    conn.receive_data(b"\x05" + SOCKS5AuthMethod.GSSAPI)
    conn.data_to_send()

    with pytest.raises(ProtocolError):
        conn.receive_data(b"\x01\x09\x00\x00")  # unexpected message type

    assert conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_malformed_protection_reply_must_close() -> None:
    context = FakeGSSAPIContext(steps_to_complete=1)
    conn = SOCKS5Connection(gssapi_context=context)
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]))
    conn.data_to_send()
    conn.receive_data(b"\x05" + SOCKS5AuthMethod.GSSAPI)
    conn.data_to_send()

    with pytest.raises(ProtocolError):
        conn.receive_data(b"\x01\x02\x00\x02\x01")  # invalid length

    assert conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_step_failure_must_close() -> None:
    class BrokenStepContext(FakeGSSAPIContext):
        def step(self, token: bytes) -> bytes:
            raise FakeGSSAPIError("cannot acquire credentials")

    conn = SOCKS5Connection(gssapi_context=BrokenStepContext())
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]))
    conn.data_to_send()

    with pytest.raises(ProtocolError):
        conn.receive_data(b"\x05" + SOCKS5AuthMethod.GSSAPI)

    assert conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_wrap_failure_must_close(
    gssapi_context: FakeGSSAPIContext,
) -> None:
    class BrokenWrapContext(FakeGSSAPIContext):
        def wrap(self, data: bytes) -> bytes:
            raise FakeGSSAPIError("context expired")

    context = BrokenWrapContext(steps_to_complete=1)
    conn = SOCKS5Connection(gssapi_context=context)
    drive_gssapi_handshake(conn)
    cmd_request = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    )

    with pytest.raises(ProtocolError):
        conn.send(cmd_request)

    assert conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_command_request_and_reply_are_protected(
    protected_conn: SOCKS5Connection,
    gssapi_context: FakeGSSAPIContext,
) -> None:
    cmd_request = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    )
    protected_conn.send(cmd_request)

    assert protected_conn.data_to_send() == protected_record(cmd_request.dumps())
    assert gssapi_context.wrap_calls == 1

    reply_data = b"\x05\x00\x00\x01\x7f\x00\x00\x01" + (1080).to_bytes(2, "big")
    results = feed_byte_by_byte(protected_conn, protected_record(reply_data))

    assert all(result is None for result in results[:-1])
    assert results[-1] == SOCKS5Reply(
        reply_code=SOCKS5ReplyCode.SUCCEEDED,
        atype=SOCKS5AType.IPV4_ADDRESS,
        addr="127.0.0.1",
        port=1080,
    )
    assert protected_conn.state == SOCKS5State.TUNNEL_READY
    assert gssapi_context.unwrap_calls == 1


def test_gssapi_application_data_is_protected(
    tunnel_conn: SOCKS5Connection, gssapi_context: FakeGSSAPIContext
) -> None:
    tunnel_conn.send_data(b"hello")
    assert tunnel_conn.data_to_send() == protected_record(b"hello")
    assert gssapi_context.wrap_calls == 2  # command request + application data

    results = feed_byte_by_byte(tunnel_conn, protected_record(b"world"))
    assert all(result is None for result in results[:-1])
    assert results[-1] == b"world"
    assert gssapi_context.unwrapped_data[-1] == b"world"


def test_gssapi_corrupted_record_is_not_delivered(
    tunnel_conn: SOCKS5Connection,
    gssapi_context: FakeGSSAPIContext,
) -> None:
    record = bytearray(protected_record(b"secret"))
    record[2] ^= 0xFF  # corrupt the authentication tag

    unwrapped_before = list(gssapi_context.unwrapped_data)
    for i in range(len(record) - 1):
        assert tunnel_conn.receive_data(record[i : i + 1]) is None

    with pytest.raises(ProtocolError):
        tunnel_conn.receive_data(record[-1:])

    # The plaintext never became application data...
    assert gssapi_context.unwrapped_data == unwrapped_before
    assert b"secret" not in gssapi_context.unwrapped_data
    # ...and the connection cannot fall back to plaintext afterwards.
    assert tunnel_conn.state == SOCKS5State.MUST_CLOSE
    with pytest.raises(ProtocolError):
        tunnel_conn.receive_data(b"secret")
    with pytest.raises(ProtocolError):
        tunnel_conn.send_data(b"hello")


def test_gssapi_no_protection_negotiated_passes_plaintext() -> None:
    context = FakeGSSAPIContext(steps_to_complete=1)
    conn = SOCKS5Connection(gssapi_context=context)
    drive_gssapi_handshake(conn, server_protection=SOCKS5GSSAPIProtectionLevel.NONE)
    assert conn.state == SOCKS5State.CLIENT_AUTHENTICATED

    cmd_request = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    )
    conn.send(cmd_request)
    assert conn.data_to_send() == cmd_request.dumps()
    assert context.wrap_calls == 0

    reply_data = b"\x05\x00\x00\x01\x7f\x00\x00\x01" + (1080).to_bytes(2, "big")
    reply = conn.receive_data(reply_data)
    assert isinstance(reply, SOCKS5Reply)
    assert conn.state == SOCKS5State.TUNNEL_READY
    assert context.unwrap_calls == 0

    conn.send_data(b"hello")
    assert conn.data_to_send() == b"hello"
    assert conn.receive_data(b"world") == b"world"


def test_send_data_requires_ready_tunnel() -> None:
    conn = SOCKS5Connection()
    with pytest.raises(ProtocolError):
        conn.send_data(b"hello")
