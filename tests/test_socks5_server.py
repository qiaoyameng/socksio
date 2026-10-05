import typing

import pytest

from socksio import (
    ProtocolError,
    SOCKS5AType,
    SOCKS5AuthMethod,
    SOCKS5AuthMethodsReceived,
    SOCKS5AuthMethodsRequest,
    SOCKS5Command,
    SOCKS5CommandReceived,
    SOCKS5CommandRequest,
    SOCKS5Connection,
    SOCKS5DataReceived,
    SOCKS5Reply,
    SOCKS5ReplyCode,
    SOCKS5ServerConnection,
    SOCKS5UsernamePasswordReceived,
    SOCKS5UsernamePasswordRequest,
)
from socksio.socks5 import SOCKS5ServerState, SOCKS5State


def client_to_server(
    client: SOCKS5Connection, server: SOCKS5ServerConnection
) -> typing.List[typing.Any]:
    return server.receive_data(client.data_to_send())


def server_to_client(
    server: SOCKS5ServerConnection, client: SOCKS5Connection
) -> typing.Any:
    return client.receive_data(server.data_to_send())


def handshake_no_auth(
    client: SOCKS5Connection, server: SOCKS5ServerConnection
) -> None:
    client.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED]))
    events = client_to_server(client, server)
    assert events == [
        SOCKS5AuthMethodsReceived(methods=[SOCKS5AuthMethod.NO_AUTH_REQUIRED])
    ]
    assert server.authenticate(SOCKS5AuthMethod.NO_AUTH_REQUIRED) == []
    reply = server_to_client(server, client)
    assert reply.method == SOCKS5AuthMethod.NO_AUTH_REQUIRED


def test_no_auth_handshake_and_payload_delivery() -> None:
    client = SOCKS5Connection()
    server = SOCKS5ServerConnection()

    handshake_no_auth(client, server)
    assert server.state == SOCKS5ServerState.WAITING_FOR_COMMAND

    client.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, "example.com:8080")
    )
    events = client_to_server(client, server)
    assert events == [
        SOCKS5CommandReceived(
            command=SOCKS5Command.CONNECT,
            atype=SOCKS5AType.DOMAIN_NAME,
            addr="example.com",
            port=8080,
        )
    ]
    assert server.state == SOCKS5ServerState.WAITING_FOR_COMMAND_DECISION

    events = server.send_command_reply(
        SOCKS5Reply(
            reply_code=SOCKS5ReplyCode.SUCCEEDED,
            atype=SOCKS5AType.IPV4_ADDRESS,
            addr="0.0.0.0",
            port=0,
        )
    )
    assert events == []
    reply = server_to_client(server, client)
    assert reply.reply_code == SOCKS5ReplyCode.SUCCEEDED
    assert client.state == SOCKS5State.TUNNEL_READY
    assert server.state == SOCKS5ServerState.TUNNEL_READY

    events = server.receive_data(b"hello")
    assert events == [SOCKS5DataReceived(data=b"hello")]
    assert server.data_to_send() == b""


def test_username_password_handshake() -> None:
    client = SOCKS5Connection()
    server = SOCKS5ServerConnection()

    client.send(
        SOCKS5AuthMethodsRequest(
            [SOCKS5AuthMethod.NO_AUTH_REQUIRED, SOCKS5AuthMethod.USERNAME_PASSWORD]
        )
    )
    events = client_to_server(client, server)
    assert events == [
        SOCKS5AuthMethodsReceived(
            methods=[
                SOCKS5AuthMethod.NO_AUTH_REQUIRED,
                SOCKS5AuthMethod.USERNAME_PASSWORD,
            ]
        )
    ]

    assert server.authenticate(SOCKS5AuthMethod.USERNAME_PASSWORD) == []
    reply = server_to_client(server, client)
    assert reply.method == SOCKS5AuthMethod.USERNAME_PASSWORD
    assert server.state == SOCKS5ServerState.WAITING_FOR_USERNAME_PASSWORD

    client.send(SOCKS5UsernamePasswordRequest(username=b"user", password=b"pass"))
    events = client_to_server(client, server)
    assert events == [
        SOCKS5UsernamePasswordReceived(username=b"user", password=b"pass")
    ]
    assert server.state == SOCKS5ServerState.WAITING_FOR_USERNAME_PASSWORD_DECISION

    assert server.authenticate_username_password(success=True) == []
    reply = server_to_client(server, client)
    assert reply.success is True
    assert server.state == SOCKS5ServerState.WAITING_FOR_COMMAND

    client.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, "127.0.0.1:8080")
    )
    events = client_to_server(client, server)
    assert events == [
        SOCKS5CommandReceived(
            command=SOCKS5Command.CONNECT,
            atype=SOCKS5AType.IPV4_ADDRESS,
            addr="127.0.0.1",
            port=8080,
        )
    ]


def test_username_password_failure_closes_connection() -> None:
    client = SOCKS5Connection()
    server = SOCKS5ServerConnection()

    client.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.USERNAME_PASSWORD]))
    client_to_server(client, server)
    server.authenticate(SOCKS5AuthMethod.USERNAME_PASSWORD)
    server_to_client(server, client)

    client.send(SOCKS5UsernamePasswordRequest(username=b"user", password=b"wrong"))
    events = client_to_server(client, server)
    assert isinstance(events[0], SOCKS5UsernamePasswordReceived)

    assert server.authenticate_username_password(success=False) == []
    reply = server_to_client(server, client)
    assert reply.success is False
    assert client.state == SOCKS5State.MUST_CLOSE
    assert server.state == SOCKS5ServerState.CLOSED

    with pytest.raises(ProtocolError):
        server.receive_data(
            SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED]).dumps()
        )


@pytest.mark.parametrize(
    "address,expected_atype,expected_addr,expected_port",
    [
        ("127.0.0.1:8080", SOCKS5AType.IPV4_ADDRESS, "127.0.0.1", 8080),
        ("[0:0:0:0:0:0:0:1]:3080", SOCKS5AType.IPV6_ADDRESS, "::1", 3080),
        ("example.com:8080", SOCKS5AType.DOMAIN_NAME, "example.com", 8080),
    ],
)
def test_connect_command_address_types(
    address: str,
    expected_atype: SOCKS5AType,
    expected_addr: str,
    expected_port: int,
) -> None:
    client = SOCKS5Connection()
    server = SOCKS5ServerConnection()
    handshake_no_auth(client, server)

    client.send(SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, address))
    events = client_to_server(client, server)

    assert events == [
        SOCKS5CommandReceived(
            command=SOCKS5Command.CONNECT,
            atype=expected_atype,
            addr=expected_addr,
            port=expected_port,
        )
    ]


def test_fragmented_data_is_buffered_until_complete() -> None:
    server = SOCKS5ServerConnection()
    data = SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED]).dumps()

    for byte in data[:-1]:
        assert server.receive_data(bytes([byte])) == []
    events = server.receive_data(data[-1:])

    assert events == [
        SOCKS5AuthMethodsReceived(methods=[SOCKS5AuthMethod.NO_AUTH_REQUIRED])
    ]


def test_premature_command_is_buffered_until_decision() -> None:
    server = SOCKS5ServerConnection()
    auth_request = SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED]).dumps()
    command_request = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "example.com:8080"
    ).dumps()

    events = server.receive_data(auth_request + command_request)

    assert events == [
        SOCKS5AuthMethodsReceived(methods=[SOCKS5AuthMethod.NO_AUTH_REQUIRED])
    ]
    assert server.state == SOCKS5ServerState.WAITING_FOR_AUTH_METHOD_DECISION

    events = server.authenticate(SOCKS5AuthMethod.NO_AUTH_REQUIRED)
    assert events == [
        SOCKS5CommandReceived(
            command=SOCKS5Command.CONNECT,
            atype=SOCKS5AType.DOMAIN_NAME,
            addr="example.com",
            port=8080,
        )
    ]


def test_premature_command_is_not_an_authenticated_command() -> None:
    server = SOCKS5ServerConnection()
    auth_request = SOCKS5AuthMethodsRequest(
        [SOCKS5AuthMethod.USERNAME_PASSWORD]
    ).dumps()
    command_request = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "example.com:8080"
    ).dumps()

    events = server.receive_data(auth_request + command_request)
    assert not any(isinstance(event, SOCKS5CommandReceived) for event in events)
    assert server.state == SOCKS5ServerState.WAITING_FOR_AUTH_METHOD_DECISION

    # The application negotiates username/password: the buffered command
    # bytes are not valid sub-negotiation data and must not be treated as
    # an authenticated command.
    with pytest.raises(ProtocolError):
        server.authenticate(SOCKS5AuthMethod.USERNAME_PASSWORD)
    assert server.state == SOCKS5ServerState.CLOSED


def test_unnegotiated_username_password_packet_is_rejected() -> None:
    server = SOCKS5ServerConnection()
    packet = SOCKS5UsernamePasswordRequest(username=b"u", password=b"p").dumps()

    with pytest.raises(ProtocolError):
        server.receive_data(packet)
    assert server.state == SOCKS5ServerState.CLOSED

    # The connection cannot recover into an authenticated state.
    with pytest.raises(ProtocolError):
        server.receive_data(
            SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED]).dumps()
        )
    assert server.state == SOCKS5ServerState.CLOSED


def test_unnegotiated_auth_method_after_no_auth_selection() -> None:
    client = SOCKS5Connection()
    server = SOCKS5ServerConnection()
    handshake_no_auth(client, server)

    packet = SOCKS5UsernamePasswordRequest(username=b"u", password=b"p").dumps()
    with pytest.raises(ProtocolError):
        server.receive_data(packet + b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90")
    assert server.state == SOCKS5ServerState.CLOSED


def test_command_bytes_before_any_negotiation_are_not_a_command() -> None:
    server = SOCKS5ServerConnection()
    command_request = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:8080"
    ).dumps()

    events = server.receive_data(command_request)

    assert not any(isinstance(event, SOCKS5CommandReceived) for event in events)
    assert server.state != SOCKS5ServerState.TUNNEL_READY


def test_pending_input_limit_is_enforced() -> None:
    server = SOCKS5ServerConnection(max_pending_bytes=8)

    with pytest.raises(ProtocolError):
        server.receive_data(b"\x05\x20" + b"\x00" * 16)
    assert server.state == SOCKS5ServerState.CLOSED

    with pytest.raises(ProtocolError):
        server.receive_data(b"\x05\x01\x00")


def test_pending_input_limit_while_decision_is_pending() -> None:
    server = SOCKS5ServerConnection(max_pending_bytes=16)
    auth_request = SOCKS5AuthMethodsRequest(
        [SOCKS5AuthMethod.USERNAME_PASSWORD]
    ).dumps()

    events = server.receive_data(auth_request)
    assert len(events) == 1

    with pytest.raises(ProtocolError):
        server.receive_data(b"\x00" * 32)
    assert server.state == SOCKS5ServerState.CLOSED


def test_payload_is_not_limited_once_tunnel_is_ready() -> None:
    client = SOCKS5Connection()
    server = SOCKS5ServerConnection(max_pending_bytes=16)
    handshake_no_auth(client, server)

    client.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, "127.0.0.1:8080")
    )
    client_to_server(client, server)
    server.send_command_reply(
        SOCKS5Reply(
            reply_code=SOCKS5ReplyCode.SUCCEEDED,
            atype=SOCKS5AType.IPV4_ADDRESS,
            addr="0.0.0.0",
            port=0,
        )
    )

    payload = b"x" * 4096
    assert server.receive_data(payload) == [SOCKS5DataReceived(data=payload)]


def test_protocol_error_is_terminal() -> None:
    server = SOCKS5ServerConnection()

    with pytest.raises(ProtocolError):
        server.receive_data(b"\x04\x01\x00")

    assert server.state == SOCKS5ServerState.CLOSED
    with pytest.raises(ProtocolError):
        server.receive_data(b"\x05\x01\x00")
    with pytest.raises(ProtocolError):
        server.authenticate(SOCKS5AuthMethod.NO_AUTH_REQUIRED)
    with pytest.raises(ProtocolError):
        server.authenticate_username_password(success=True)


def test_unsupported_command_is_refused() -> None:
    client = SOCKS5Connection()
    server = SOCKS5ServerConnection()
    handshake_no_auth(client, server)

    bind_request = SOCKS5CommandRequest.from_address(
        SOCKS5Command.BIND, "127.0.0.1:8080"
    ).dumps()
    events = server.receive_data(bind_request)

    assert events == []
    assert server.state == SOCKS5ServerState.CLOSED
    reply = SOCKS5Reply.loads(server.data_to_send())
    assert reply.reply_code == SOCKS5ReplyCode.COMMAND_NOT_SUPPORTED


def test_no_acceptable_methods_closes_connection() -> None:
    server = SOCKS5ServerConnection()
    server.receive_data(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.GSSAPI]).dumps())

    assert server.authenticate(SOCKS5AuthMethod.NO_ACCEPTABLE_METHODS) == []

    assert server.data_to_send() == b"\x05\xff"
    assert server.state == SOCKS5ServerState.CLOSED


def test_failed_command_reply_closes_connection() -> None:
    client = SOCKS5Connection()
    server = SOCKS5ServerConnection()
    handshake_no_auth(client, server)

    client.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, "example.com:8080")
    )
    client_to_server(client, server)
    server.send_command_reply(
        SOCKS5Reply(
            reply_code=SOCKS5ReplyCode.CONNECTION_REFUSED,
            atype=SOCKS5AType.IPV4_ADDRESS,
            addr="0.0.0.0",
            port=0,
        )
    )

    reply = server_to_client(server, client)
    assert reply.reply_code == SOCKS5ReplyCode.CONNECTION_REFUSED
    assert server.state == SOCKS5ServerState.CLOSED


def test_decisions_in_wrong_state_raise() -> None:
    server = SOCKS5ServerConnection()

    with pytest.raises(ProtocolError):
        server.authenticate(SOCKS5AuthMethod.NO_AUTH_REQUIRED)
    with pytest.raises(ProtocolError):
        server.authenticate_username_password(success=True)
    with pytest.raises(ProtocolError):
        server.send_command_reply(
            SOCKS5Reply(
                reply_code=SOCKS5ReplyCode.SUCCEEDED,
                atype=SOCKS5AType.IPV4_ADDRESS,
                addr="0.0.0.0",
                port=0,
            )
        )
    assert server.state == SOCKS5ServerState.WAITING_FOR_AUTH_METHODS


def test_invalid_max_pending_bytes() -> None:
    with pytest.raises(ValueError):
        SOCKS5ServerConnection(max_pending_bytes=0)
