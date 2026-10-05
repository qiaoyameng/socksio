import typing

import pytest

from socksio import (
    ProtocolError,
    SOCKS4ARequest,
    SOCKS4Command,
    SOCKS4Connection,
    SOCKS4Reply,
    SOCKS4ReplyCode,
    SOCKS4Request,
    SOCKS4State,
    SOCKSError,
)


@pytest.mark.parametrize(
    "address,expected_address,expected_port",
    [
        (("127.0.0.1", 3080), b"\x7f\x00\x00\x01", 3080),
        (("127.0.0.1", "3080"), b"\x7f\x00\x00\x01", 3080),
        ("127.0.0.1:8080", b"\x7f\x00\x00\x01", 8080),
        ((b"127.0.0.1", 3080), b"\x7f\x00\x00\x01", 3080),
        ((b"127.0.0.1", b"3080"), b"\x7f\x00\x00\x01", 3080),
        (b"127.0.0.1:8080", b"\x7f\x00\x00\x01", 8080),
    ],
)
def test_socks4request_from_address(address, expected_address, expected_port) -> None:
    req = SOCKS4Request.from_address(SOCKS4Command.CONNECT, address, user_id=b"socksio")

    assert req.command == SOCKS4Command.CONNECT
    assert req.addr == expected_address
    assert req.port == expected_port
    assert req.user_id == b"socksio"


@pytest.mark.parametrize(
    "address,user_id",
    [
        (("::1", 3080), b"socksio"),  # IPV6
        ("localhost:3080", b"socksio"),  # Domain names
    ],
)
def test_socks4request_from_address_errors(address, user_id) -> None:
    with pytest.raises(SOCKSError):
        SOCKS4Request.from_address(
            command=SOCKS4Command.BIND, address=address, user_id=user_id
        )


def test_socks4request_from_address_dump_raises_if_no_user_id():
    req = SOCKS4Request.from_address(SOCKS4Command.CONNECT, "127.0.0.1:8080")

    with pytest.raises(SOCKSError):
        req.dumps()


@pytest.mark.parametrize(
    "address,expected_address,expected_port",
    [
        (("127.0.0.1", 3080), b"\x7f\x00\x00\x01", 3080),
        (("127.0.0.1", "3080"), b"\x7f\x00\x00\x01", 3080),
        ("127.0.0.1:8080", b"\x7f\x00\x00\x01", 8080),
        ((b"127.0.0.1", 3080), b"\x7f\x00\x00\x01", 3080),
        ((b"127.0.0.1", b"3080"), b"\x7f\x00\x00\x01", 3080),
        (b"127.0.0.1:8080", b"\x7f\x00\x00\x01", 8080),
    ],
)
def test_socks4arequest_from_address(address, expected_address, expected_port) -> None:
    req = SOCKS4ARequest.from_address(
        SOCKS4Command.CONNECT, address, user_id=b"socksio"
    )

    assert req.command == SOCKS4Command.CONNECT
    assert req.addr == expected_address
    assert req.port == expected_port
    assert req.user_id == b"socksio"


def test_socks4arequest_from_address_dump_raises_if_no_user_id():
    req = SOCKS4ARequest.from_address(SOCKS4Command.CONNECT, "127.0.0.1:8080")

    with pytest.raises(SOCKSError):
        req.dumps()


@pytest.mark.parametrize("command", [SOCKS4Command.BIND, SOCKS4Command.CONNECT])
def test_socks4_connection_request(command: SOCKS4Command) -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(command=command, address=("127.0.0.1", 8080))
    conn.send(request)

    data = conn.data_to_send()
    assert len(data) == 9 + 5
    assert data[0:1] == b"\x04"
    assert data[1:2] == command
    assert data[2:4] == (8080).to_bytes(2, byteorder="big")
    assert data[4:8] == b"\x7f\x00\x00\x01"
    assert data[8:13] == b"socks"
    assert data[13] == 0


@pytest.mark.parametrize("request_reply_code", list(SOCKS4ReplyCode))
def test_socks4_receive_data(request_reply_code: bytes) -> None:
    conn = SOCKS4Connection(user_id=b"socks")

    reply = conn.receive_data(
        b"".join(
            [
                b"\x00",
                request_reply_code,
                (8080).to_bytes(2, byteorder="big"),
                b"\x7f\x00\x00\x01",
            ]
        )
    )

    assert reply == SOCKS4Reply(
        reply_code=SOCKS4ReplyCode(request_reply_code), port=8080, addr="127.0.0.1"
    )


@pytest.mark.parametrize(
    "data",
    [
        b"\x0fZ\x1f\x90\x7f\x00\x00\x01",  # not starting with 0
        b"\x00\xff\x1f\x90\x7f\x00\x00\x01",  # incorrect reply code
    ],
)
def test_socks4_receive_malformed_data(data: bytes) -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(
        SOCKS4Command.CONNECT, ("127.0.0.1", 8080)
    )
    conn.send(request)

    with pytest.raises(ProtocolError):
        conn.receive_data(data)

    assert conn.state == SOCKS4State.MUST_CLOSE


def test_socks4_receive_partial_reply_then_complete() -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(
        SOCKS4Command.CONNECT, ("127.0.0.1", 8080)
    )
    conn.send(request)

    reply_data = b"".join(
        [
            b"\x00",
            SOCKS4ReplyCode.REQUEST_GRANTED,
            (8080).to_bytes(2, byteorder="big"),
            b"\x7f\x00\x00\x01",
        ]
    )

    for byte in reply_data[:-1]:
        assert conn.receive_data(bytes([byte])) is None

    assert conn.receive_data(reply_data[-1:]) == SOCKS4Reply(
        reply_code=SOCKS4ReplyCode.REQUEST_GRANTED, port=8080, addr="127.0.0.1"
    )
    assert conn.state == SOCKS4State.TUNNEL_READY


@pytest.mark.parametrize("command", [SOCKS4Command.BIND, SOCKS4Command.CONNECT])
def test_SOCKS4A_connection_request(command: SOCKS4Command) -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4ARequest.from_address(
        command=command, address=("proxy.example.com", 8080)
    )
    conn.send(request)

    data = conn.data_to_send()
    assert len(data) == 32
    assert data[0:1] == b"\x04"
    assert data[1:2] == command
    assert data[2:4] == (8080).to_bytes(2, byteorder="big")
    assert data[4:8] == b"\x00\x00\x00\xff"
    assert data[8:14] == b"socks\x00"
    assert data[14:] == b"proxy.example.com\x00"


def _socks4_bind_reply(reply_code: SOCKS4ReplyCode, port: int = 8080) -> bytes:
    return b"".join(
        [
            b"\x00",
            reply_code,
            port.to_bytes(2, byteorder="big"),
            b"\x7f\x00\x00\x01",
        ]
    )


def _feed_byte_by_byte(conn: SOCKS4Connection, data: bytes) -> typing.List[SOCKS4Reply]:
    events = []
    for byte in data:
        event = conn.receive_data(bytes([byte]))
        if event is not None:
            events.append(event)
    return events


def test_socks4_bind_send_sets_waiting_state() -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(
        SOCKS4Command.BIND, ("127.0.0.1", 8080)
    )
    conn.send(request)

    assert conn.state == SOCKS4State.SERVER_BIND_REPLY


def test_socks4_bind_cannot_send_another_command_while_waiting() -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(
        SOCKS4Command.BIND, ("127.0.0.1", 8080)
    )
    conn.send(request)

    with pytest.raises(ProtocolError):
        conn.send(request)

    first_reply = _socks4_bind_reply(SOCKS4ReplyCode.REQUEST_GRANTED)
    assert conn.receive_data(first_reply).reply_code == (
        SOCKS4ReplyCode.REQUEST_GRANTED
    )
    assert conn.state == SOCKS4State.SERVER_BIND_PEER_REPLY

    with pytest.raises(ProtocolError):
        conn.send(request)


def test_socks4_bind_first_success_is_not_tunnel_ready() -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(
        SOCKS4Command.BIND, ("127.0.0.1", 8080)
    )
    conn.send(request)

    event = conn.receive_data(
        _socks4_bind_reply(SOCKS4ReplyCode.REQUEST_GRANTED, port=3080)
    )

    assert event == SOCKS4Reply(
        reply_code=SOCKS4ReplyCode.REQUEST_GRANTED, port=3080, addr="127.0.0.1"
    )
    assert conn.state == SOCKS4State.SERVER_BIND_PEER_REPLY


def test_socks4_bind_first_reply_failure_is_terminal() -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(
        SOCKS4Command.BIND, ("127.0.0.1", 8080)
    )
    conn.send(request)

    event = conn.receive_data(
        _socks4_bind_reply(SOCKS4ReplyCode.REQUEST_REJECTED_OR_FAILED)
    )

    assert event.reply_code == SOCKS4ReplyCode.REQUEST_REJECTED_OR_FAILED
    assert conn.state == SOCKS4State.MUST_CLOSE

    with pytest.raises(ProtocolError):
        conn.send(request)


def test_socks4_bind_first_success_second_failure_byte_by_byte() -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(
        SOCKS4Command.BIND, ("127.0.0.1", 8080)
    )
    conn.send(request)

    first_reply = _socks4_bind_reply(
        SOCKS4ReplyCode.REQUEST_GRANTED, port=3080
    )
    events = _feed_byte_by_byte(conn, first_reply)

    assert events == [
        SOCKS4Reply(
            reply_code=SOCKS4ReplyCode.REQUEST_GRANTED,
            port=3080,
            addr="127.0.0.1",
        )
    ]
    assert conn.state == SOCKS4State.SERVER_BIND_PEER_REPLY

    second_reply = _socks4_bind_reply(SOCKS4ReplyCode.CONNECTION_FAILED)
    events = _feed_byte_by_byte(conn, second_reply)

    assert events == [
        SOCKS4Reply(
            reply_code=SOCKS4ReplyCode.CONNECTION_FAILED,
            port=8080,
            addr="127.0.0.1",
        )
    ]
    assert conn.state == SOCKS4State.MUST_CLOSE


def test_socks4_bind_both_replies_succeed_byte_by_byte() -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(
        SOCKS4Command.BIND, ("127.0.0.1", 8080)
    )
    conn.send(request)

    first_reply = _socks4_bind_reply(
        SOCKS4ReplyCode.REQUEST_GRANTED, port=3080
    )
    second_reply = _socks4_bind_reply(
        SOCKS4ReplyCode.REQUEST_GRANTED, port=4567
    )

    events = _feed_byte_by_byte(conn, first_reply + second_reply)

    assert events == [
        SOCKS4Reply(
            reply_code=SOCKS4ReplyCode.REQUEST_GRANTED,
            port=3080,
            addr="127.0.0.1",
        ),
        SOCKS4Reply(
            reply_code=SOCKS4ReplyCode.REQUEST_GRANTED,
            port=4567,
            addr="127.0.0.1",
        ),
    ]
    assert conn.state == SOCKS4State.TUNNEL_READY


def test_socks4_bind_second_reply_piggybacks_tunnel_data() -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(
        SOCKS4Command.BIND, ("127.0.0.1", 8080)
    )
    conn.send(request)
    conn.receive_data(_socks4_bind_reply(SOCKS4ReplyCode.REQUEST_GRANTED))

    tunnel_data = b"first bytes from the connected peer"
    event = conn.receive_data(
        _socks4_bind_reply(SOCKS4ReplyCode.REQUEST_GRANTED) + tunnel_data
    )

    assert event.reply_code == SOCKS4ReplyCode.REQUEST_GRANTED
    assert conn.state == SOCKS4State.TUNNEL_READY
    assert conn.tunnel_data() == tunnel_data
    assert conn.tunnel_data() == b""


def test_socks4_connect_flow_still_works_with_bind_states() -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    request = SOCKS4Request.from_address(
        SOCKS4Command.CONNECT, ("127.0.0.1", 8080)
    )
    conn.send(request)

    assert conn.state == SOCKS4State.SERVER_REPLY

    events = _feed_byte_by_byte(
        conn, _socks4_bind_reply(SOCKS4ReplyCode.REQUEST_GRANTED)
    )
    assert len(events) == 1
    assert conn.state == SOCKS4State.TUNNEL_READY
