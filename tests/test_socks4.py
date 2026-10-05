import pytest

from socksio import (
    ProtocolError,
    SOCKS4ARequest,
    SOCKS4Command,
    SOCKS4Connection,
    SOCKS4Reply,
    SOCKS4ReplyCode,
    SOCKS4Request,
    SOCKSError,
)
from socksio.socks4 import SOCKS4State


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
        b"\x00Z\x1f\x90\x7f\x00\x00",  # missing one byte
        b"\x0fZ\x1f\x90\x7f\x00\x00\x01",  # not starting with 0
        b"\x00\xff\x1f\x90\x7f\x00\x00\x01",  # incorrect reply code
    ],
)
def test_socks4_receive_malformed_data(data: bytes) -> None:
    conn = SOCKS4Connection(user_id=b"socks")

    with pytest.raises(ProtocolError):
        conn.receive_data(data)


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



def _socks4_reply(
    code: SOCKS4ReplyCode = SOCKS4ReplyCode.REQUEST_GRANTED, data: bytes = b""
) -> bytes:
    return b"".join(
        [
            b"\x00",
            code,
            (1080).to_bytes(2, byteorder="big"),
            b"\x7f\x00\x00\x01",
            data,
        ]
    )


@pytest.fixture
def bind_conn() -> SOCKS4Connection:
    conn = SOCKS4Connection(user_id=b"socks")
    conn.send(
        SOCKS4Request.from_address(SOCKS4Command.BIND, ("127.0.0.1", 1080))
    )
    conn.data_to_send()
    return conn


def _feed_byte_by_byte(conn: SOCKS4Connection, data: bytes, events: list) -> None:
    for index in range(len(data) - 1):
        assert conn.receive_data(data[index : index + 1]) is None
    events.append(conn.receive_data(data[-1:]))


def test_socks4_bind_first_success_is_not_tunnel_ready(
    bind_conn: SOCKS4Connection
) -> None:
    events = []
    _feed_byte_by_byte(bind_conn, _socks4_reply(), events)

    assert events == [
        SOCKS4Reply(
            reply_code=SOCKS4ReplyCode.REQUEST_GRANTED, port=1080, addr="127.0.0.1"
        )
    ]
    assert bind_conn.state == SOCKS4State.SERVER_BIND_SECOND_REPLY


def test_socks4_bind_second_success_opens_tunnel(bind_conn: SOCKS4Connection) -> None:
    events = []
    _feed_byte_by_byte(bind_conn, _socks4_reply(), events)
    _feed_byte_by_byte(bind_conn, _socks4_reply(), events)

    assert events == [
        SOCKS4Reply(
            reply_code=SOCKS4ReplyCode.REQUEST_GRANTED, port=1080, addr="127.0.0.1"
        ),
        SOCKS4Reply(
            reply_code=SOCKS4ReplyCode.REQUEST_GRANTED, port=1080, addr="127.0.0.1"
        ),
    ]
    assert bind_conn.state == SOCKS4State.TUNNEL_READY


@pytest.mark.parametrize(
    "waiting_state",
    [SOCKS4State.SERVER_BIND_FIRST_REPLY, SOCKS4State.SERVER_BIND_SECOND_REPLY],
)
def test_socks4_bind_rejects_another_command_while_waiting(
    bind_conn: SOCKS4Connection, waiting_state: SOCKS4State
) -> None:
    if waiting_state == SOCKS4State.SERVER_BIND_SECOND_REPLY:
        _feed_byte_by_byte(bind_conn, _socks4_reply(), [])
    assert bind_conn.state == waiting_state

    with pytest.raises(ProtocolError):
        bind_conn.send(
            SOCKS4Request.from_address(SOCKS4Command.BIND, ("127.0.0.1", 1080))
        )
    with pytest.raises(ProtocolError):
        bind_conn.send(
            SOCKS4Request.from_address(SOCKS4Command.CONNECT, ("127.0.0.1", 1080))
        )


def test_socks4_bind_first_failure_is_terminal(bind_conn: SOCKS4Connection) -> None:
    events = []
    _feed_byte_by_byte(
        bind_conn, _socks4_reply(SOCKS4ReplyCode.CONNECTION_FAILED), events
    )

    assert events == [
        SOCKS4Reply(
            reply_code=SOCKS4ReplyCode.CONNECTION_FAILED, port=1080, addr="127.0.0.1"
        )
    ]
    assert bind_conn.state == SOCKS4State.MUST_CLOSE


def test_socks4_bind_second_failure_is_terminal(bind_conn: SOCKS4Connection) -> None:
    events = []
    _feed_byte_by_byte(bind_conn, _socks4_reply(), events)
    _feed_byte_by_byte(
        bind_conn, _socks4_reply(SOCKS4ReplyCode.CONNECTION_FAILED), events
    )

    assert events[0].reply_code == SOCKS4ReplyCode.REQUEST_GRANTED
    assert events[1].reply_code == SOCKS4ReplyCode.CONNECTION_FAILED
    assert bind_conn.state == SOCKS4State.MUST_CLOSE


def test_socks4_bind_two_replies_with_tunnel_data_in_same_chunk(
    bind_conn: SOCKS4Connection,
) -> None:
    first_reply = _socks4_reply()
    second_reply = _socks4_reply(data=b"hello")
    events = []
    events.append(bind_conn.receive_data(first_reply + second_reply))
    events.append(bind_conn.receive_data(b""))

    assert events == [
        SOCKS4Reply(
            reply_code=SOCKS4ReplyCode.REQUEST_GRANTED, port=1080, addr="127.0.0.1"
        ),
        SOCKS4Reply(
            reply_code=SOCKS4ReplyCode.REQUEST_GRANTED, port=1080, addr="127.0.0.1"
        ),
    ]
    assert bind_conn.state == SOCKS4State.TUNNEL_READY
    assert bind_conn.receive_data(b" world") == b"hello world"


def test_socks4_connect_flow_unchanged() -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    assert conn.state == SOCKS4State.CLIENT_REQUEST_REQUIRED

    conn.send(
        SOCKS4Request.from_address(SOCKS4Command.CONNECT, ("127.0.0.1", 1080))
    )
    assert conn.state == SOCKS4State.SERVER_REPLY

    reply = conn.receive_data(_socks4_reply())

    assert reply == SOCKS4Reply(
        reply_code=SOCKS4ReplyCode.REQUEST_GRANTED, port=1080, addr="127.0.0.1"
    )
    assert conn.state == SOCKS4State.TUNNEL_READY
    assert conn.receive_data(b"tunnel data") == b"tunnel data"


def test_socks4_connect_failure_is_terminal() -> None:
    conn = SOCKS4Connection(user_id=b"socks")
    conn.send(
        SOCKS4Request.from_address(SOCKS4Command.CONNECT, ("127.0.0.1", 1080))
    )

    conn.receive_data(_socks4_reply(SOCKS4ReplyCode.CONNECTION_FAILED))

    assert conn.state == SOCKS4State.MUST_CLOSE
