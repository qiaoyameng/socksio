import typing

import pytest

from fake_gssapi import FakeGSSAPIContext, server_message, server_unwrap, server_wrap
from socksio import (
    GSSAPIProtectionLevel,
    ProtocolError,
    SOCKS5AType,
    SOCKS5AuthMethod,
    SOCKS5AuthMethodsRequest,
    SOCKS5Command,
    SOCKS5CommandRequest,
    SOCKS5Connection,
    SOCKS5ReplyCode,
)
from socksio.gssapi import GSSAPIMessageType, decode_message
from socksio.socks5 import SOCKS5State


class ClientDriver:
    """Drives a SOCKS5Connection, buffering framed output so that individual
    messages can be popped even when several are queued at once."""

    def __init__(self, conn: SOCKS5Connection) -> None:
        self.conn = conn
        self._buffer = bytearray()

    def pop_message(self) -> typing.Tuple[GSSAPIMessageType, bytes]:
        decoded = decode_message(self._buffer)
        if decoded is None:
            self._buffer += self.conn.data_to_send()
            decoded = decode_message(self._buffer)
        assert decoded is not None
        return decoded


def start_gssapi_connection(
    context: FakeGSSAPIContext,
    min_protection: GSSAPIProtectionLevel = GSSAPIProtectionLevel.INTEGRITY,
) -> ClientDriver:
    conn = SOCKS5Connection(
        gssapi_context=context, min_gssapi_protection=min_protection
    )
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]))
    conn.data_to_send()
    reply = conn.receive_data(b"\x05" + SOCKS5AuthMethod.GSSAPI)
    assert reply is not None and reply.method == SOCKS5AuthMethod.GSSAPI
    assert conn.state == SOCKS5State.CLIENT_GSSAPI_AUTHENTICATION
    return ClientDriver(conn)


def drive_token_exchange(driver: ClientDriver, rounds: int) -> None:
    for round_number in range(1, rounds + 1):
        message_type, token = driver.pop_message()
        assert message_type == GSSAPIMessageType.AUTHENTICATION
        assert token == b"client-token-%d" % round_number
        if round_number == rounds:
            break
        assert (
            driver.conn.receive_data(
                server_message(
                    GSSAPIMessageType.AUTHENTICATION,
                    b"server-token-%d" % round_number,
                )
            )
            is None
        )


def drive_protection_negotiation(
    driver: ClientDriver,
    level: GSSAPIProtectionLevel = GSSAPIProtectionLevel.CONFIDENTIALITY,
) -> None:
    message_type, token = driver.pop_message()
    assert message_type == GSSAPIMessageType.PROTECTION_NEGOTIATION
    assert server_unwrap(token) == bytes([GSSAPIProtectionLevel.INTEGRITY])
    driver.conn.receive_data(
        server_message(
            GSSAPIMessageType.PROTECTION_NEGOTIATION, server_wrap(bytes([level]))
        )
    )


def authenticated_driver(
    steps_to_complete: int = 1,
    level: GSSAPIProtectionLevel = GSSAPIProtectionLevel.CONFIDENTIALITY,
    min_protection: GSSAPIProtectionLevel = GSSAPIProtectionLevel.INTEGRITY,
) -> typing.Tuple[ClientDriver, FakeGSSAPIContext]:
    context = FakeGSSAPIContext(steps_to_complete=steps_to_complete)
    driver = start_gssapi_connection(context, min_protection=min_protection)
    drive_token_exchange(driver, steps_to_complete)
    drive_protection_negotiation(driver, level=level)
    assert driver.conn.state == SOCKS5State.CLIENT_AUTHENTICATED
    assert driver.conn.gssapi_protection == level
    return driver, context


def establish_tunnel(driver: ClientDriver) -> None:
    conn = driver.conn
    conn.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, "127.0.0.1:8080")
    )
    conn.data_to_send()
    reply = conn.receive_data(
        server_message(
            GSSAPIMessageType.SUBSEQUENT_MESSAGE,
            server_wrap(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x0c\x08"),
        )
    )
    assert reply is not None and reply.reply_code == SOCKS5ReplyCode.SUCCEEDED
    assert conn.state == SOCKS5State.TUNNEL_READY


def test_gssapi_multiround_handshake_call_counts() -> None:
    context = FakeGSSAPIContext(steps_to_complete=3)
    driver = start_gssapi_connection(context)

    drive_token_exchange(driver, 3)
    assert context.step_calls == 3
    assert context.stepped_tokens == [b"", b"server-token-1", b"server-token-2"]
    assert context.complete
    assert driver.conn.state == SOCKS5State.CLIENT_GSSAPI_AUTHENTICATION

    drive_protection_negotiation(driver)
    assert context.wrap_calls == 1
    assert context.unwrap_calls == 1
    assert driver.conn.state == SOCKS5State.CLIENT_AUTHENTICATED
    assert driver.conn.gssapi_protection == GSSAPIProtectionLevel.CONFIDENTIALITY


def test_gssapi_negotiation_record_fed_byte_by_byte() -> None:
    context = FakeGSSAPIContext(steps_to_complete=1)
    driver = start_gssapi_connection(context)
    drive_token_exchange(driver, 1)
    driver.pop_message()

    record = server_message(
        GSSAPIMessageType.PROTECTION_NEGOTIATION,
        server_wrap(bytes([GSSAPIProtectionLevel.INTEGRITY])),
    )
    for byte in record[:-1]:
        assert driver.conn.receive_data(bytes([byte])) is None
        assert driver.conn.state == SOCKS5State.CLIENT_GSSAPI_AUTHENTICATION
    assert driver.conn.receive_data(record[-1:]) is None
    assert driver.conn.state == SOCKS5State.CLIENT_AUTHENTICATED
    assert context.unwrap_calls == 1


def test_gssapi_selected_without_context_raises() -> None:
    conn = SOCKS5Connection()
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]))
    conn.data_to_send()
    with pytest.raises(ProtocolError):
        conn.receive_data(b"\x05" + SOCKS5AuthMethod.GSSAPI)
    assert conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_server_abort_must_close() -> None:
    driver = start_gssapi_connection(FakeGSSAPIContext())
    driver.pop_message()
    with pytest.raises(ProtocolError):
        driver.conn.receive_data(b"\x01\xff\x00\x00")
    assert driver.conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_invalid_version_rejected() -> None:
    driver = start_gssapi_connection(FakeGSSAPIContext())
    driver.pop_message()
    with pytest.raises(ProtocolError):
        driver.conn.receive_data(b"\x02\x01\x00\x00")
    assert driver.conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_invalid_message_type_rejected() -> None:
    driver = start_gssapi_connection(FakeGSSAPIContext())
    driver.pop_message()
    with pytest.raises(ProtocolError):
        driver.conn.receive_data(b"\x01\x07\x00\x00")
    assert driver.conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_malformed_negotiation_length_rejected() -> None:
    driver = start_gssapi_connection(FakeGSSAPIContext())
    drive_token_exchange(driver, 1)
    driver.pop_message()
    with pytest.raises(ProtocolError):
        driver.conn.receive_data(
            server_message(
                GSSAPIMessageType.PROTECTION_NEGOTIATION,
                server_wrap(b"\x02\x02"),
            )
        )
    assert driver.conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_server_selects_no_protection_rejected() -> None:
    driver = start_gssapi_connection(FakeGSSAPIContext())
    drive_token_exchange(driver, 1)
    driver.pop_message()
    with pytest.raises(ProtocolError):
        driver.conn.receive_data(
            server_message(
                GSSAPIMessageType.PROTECTION_NEGOTIATION,
                server_wrap(bytes([GSSAPIProtectionLevel.NONE])),
            )
        )
    assert driver.conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_unknown_protection_level_rejected() -> None:
    driver = start_gssapi_connection(FakeGSSAPIContext())
    drive_token_exchange(driver, 1)
    driver.pop_message()
    with pytest.raises(ProtocolError):
        driver.conn.receive_data(
            server_message(
                GSSAPIMessageType.PROTECTION_NEGOTIATION, server_wrap(b"\x2a")
            )
        )
    assert driver.conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_below_minimum_protection_rejected_no_plaintext_fallback() -> None:
    context = FakeGSSAPIContext()
    driver = start_gssapi_connection(
        context, min_protection=GSSAPIProtectionLevel.CONFIDENTIALITY
    )
    drive_token_exchange(driver, 1)
    message_type, token = driver.pop_message()
    assert message_type == GSSAPIMessageType.PROTECTION_NEGOTIATION
    assert server_unwrap(token) == bytes([GSSAPIProtectionLevel.CONFIDENTIALITY])

    with pytest.raises(ProtocolError):
        driver.conn.receive_data(
            server_message(
                GSSAPIMessageType.PROTECTION_NEGOTIATION,
                server_wrap(bytes([GSSAPIProtectionLevel.INTEGRITY])),
            )
        )
    assert driver.conn.state == SOCKS5State.MUST_CLOSE
    with pytest.raises(ProtocolError):
        driver.conn.send(
            SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, "127.0.0.1:8080")
        )


def test_gssapi_command_request_and_reply_are_wrapped() -> None:
    driver, context = authenticated_driver()
    conn = driver.conn
    request = SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, "127.0.0.1:8080")
    conn.send(request)
    message_type, token = driver.pop_message()
    assert message_type == GSSAPIMessageType.SUBSEQUENT_MESSAGE
    assert server_unwrap(token) == request.dumps()

    wrapped_reply = server_message(
        GSSAPIMessageType.SUBSEQUENT_MESSAGE,
        server_wrap(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x0c\x08"),
    )
    reply = None
    for byte in wrapped_reply:
        reply = conn.receive_data(bytes([byte]))
    assert reply is not None
    assert reply.reply_code == SOCKS5ReplyCode.SUCCEEDED
    assert reply.atype == SOCKS5AType.IPV4_ADDRESS
    assert reply.addr == "127.0.0.1"
    assert reply.port == 3080
    assert conn.state == SOCKS5State.TUNNEL_READY


def test_gssapi_wrapped_reply_incomplete_returns_none() -> None:
    driver, context = authenticated_driver()
    conn = driver.conn
    conn.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, "127.0.0.1:8080")
    )
    conn.data_to_send()
    wrapped_reply = server_message(
        GSSAPIMessageType.SUBSEQUENT_MESSAGE,
        server_wrap(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x0c\x08"),
    )
    for byte in wrapped_reply[:-1]:
        assert conn.receive_data(bytes([byte])) is None
        assert conn.state == SOCKS5State.CLIENT_AUTHENTICATED
    reply = conn.receive_data(wrapped_reply[-1:])
    assert reply is not None and reply.reply_code == SOCKS5ReplyCode.SUCCEEDED


def test_gssapi_data_phase_records_fed_byte_by_byte() -> None:
    driver, context = authenticated_driver()
    establish_tunnel(driver)
    conn = driver.conn
    unwrap_calls_before = context.unwrap_calls

    conn.send_data(b"hello")
    message_type, token = driver.pop_message()
    assert message_type == GSSAPIMessageType.SUBSEQUENT_MESSAGE
    assert server_unwrap(token) == b"hello"

    record = server_message(
        GSSAPIMessageType.SUBSEQUENT_MESSAGE, server_wrap(b"response-1")
    ) + server_message(GSSAPIMessageType.SUBSEQUENT_MESSAGE, server_wrap(b"response-2"))
    data = b""
    for byte in record:
        chunk = conn.receive_data(bytes([byte]))
        if chunk is not None:
            data += chunk
    assert data == b"response-1response-2"
    assert context.unwrap_calls == unwrap_calls_before + 2


def test_gssapi_corrupted_record_never_becomes_application_data() -> None:
    driver, context = authenticated_driver()
    establish_tunnel(driver)
    conn = driver.conn
    unwrapped_before = list(context.unwrapped)

    record = bytearray(
        server_message(
            GSSAPIMessageType.SUBSEQUENT_MESSAGE, server_wrap(b"secret-body")
        )
    )
    record[-1] ^= 0xFF  # Corrupt the authentication tag.

    received = []
    with pytest.raises(ProtocolError):
        for byte in record:
            received.append(conn.receive_data(bytes([byte])))
    assert b"secret-body" not in received
    assert context.unwrapped == unwrapped_before
    assert conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_corrupted_command_reply_rejected() -> None:
    driver, context = authenticated_driver()
    conn = driver.conn
    conn.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, "127.0.0.1:8080")
    )
    conn.data_to_send()

    record = bytearray(
        server_message(
            GSSAPIMessageType.SUBSEQUENT_MESSAGE,
            server_wrap(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x0c\x08"),
        )
    )
    record[-1] ^= 0xFF
    with pytest.raises(ProtocolError):
        conn.receive_data(bytes(record))
    assert conn.state == SOCKS5State.MUST_CLOSE


def test_gssapi_wrong_message_type_in_data_phase_rejected() -> None:
    driver, context = authenticated_driver()
    establish_tunnel(driver)
    with pytest.raises(ProtocolError):
        driver.conn.receive_data(
            server_message(GSSAPIMessageType.AUTHENTICATION, server_wrap(b"nope"))
        )
    assert driver.conn.state == SOCKS5State.MUST_CLOSE


def test_send_data_requires_established_tunnel() -> None:
    driver, context = authenticated_driver()
    with pytest.raises(ProtocolError):
        driver.conn.send_data(b"nope")
