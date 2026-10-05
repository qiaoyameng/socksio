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
    SOCKS5DataReceived,
    SOCKS5Reply,
    SOCKS5ReplyCode,
    SOCKS5ServerConnection,
    SOCKS5UsernamePasswordReply,
    SOCKS5UsernamePasswordRequest,
)
from socksio.socks5 import SOCKS5State


@pytest.mark.parametrize(
    "target,expected_atype,expected_addr",
    [
        ("127.0.0.1:1080", SOCKS5AType.IPV4_ADDRESS, b"\x7f\x00\x00\x01"),
        ("localhost:1080", SOCKS5AType.DOMAIN_NAME, b"localhost"),
        (
            "[::1]:1080",
            SOCKS5AType.IPV6_ADDRESS,
            b"\x00" * 15 + b"\x01",
        ),
    ],
)
def test_socks5_server_no_auth_handshake_in_memory(
    target: str, expected_atype: SOCKS5AType, expected_addr: bytes
) -> None:
    client = SOCKS5Connection()
    server = SOCKS5ServerConnection()

    client.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED]))
    offered = server.receive_data(client.data_to_send())

    assert offered == SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED])
    assert server.state == SOCKS5State.SERVER_WAIT_AUTH_METHOD_DECISION
    assert server.send(SOCKS5AuthReply(SOCKS5AuthMethod.NO_AUTH_REQUIRED)) is None
    assert client.receive_data(server.data_to_send()).method == (
        SOCKS5AuthMethod.NO_AUTH_REQUIRED
    )

    client.send(SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, target))
    command = server.receive_data(client.data_to_send())

    assert command == SOCKS5CommandRequest(
        command=SOCKS5Command.CONNECT,
        atype=expected_atype,
        addr=expected_addr,
        port=1080,
    )
    assert server.state == SOCKS5State.SERVER_WAIT_COMMAND_DECISION
    reply = SOCKS5Reply.from_address(SOCKS5ReplyCode.SUCCEEDED, target)
    assert server.send(reply) is None
    client_reply = client.receive_data(server.data_to_send())

    assert server.state == SOCKS5State.TUNNEL_READY
    assert client.state == SOCKS5State.TUNNEL_READY
    assert client_reply == reply

    assert server.receive_data(b"hello") == SOCKS5DataReceived(b"hello")


def test_socks5_server_username_password_handshake_in_memory() -> None:
    client = SOCKS5Connection()
    server = SOCKS5ServerConnection()

    client.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.USERNAME_PASSWORD]))
    offered = server.receive_data(client.data_to_send())

    assert offered == SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.USERNAME_PASSWORD])
    assert server.send(SOCKS5AuthReply(SOCKS5AuthMethod.USERNAME_PASSWORD)) is None
    assert client.receive_data(server.data_to_send()).method == (
        SOCKS5AuthMethod.USERNAME_PASSWORD
    )

    client.send(SOCKS5UsernamePasswordRequest(b"user", b"pass"))
    credentials = server.receive_data(client.data_to_send())

    assert credentials == SOCKS5UsernamePasswordRequest(b"user", b"pass")
    assert server.state == SOCKS5State.SERVER_WAIT_AUTH_DECISION
    assert server.send(SOCKS5UsernamePasswordReply(success=True)) is None
    assert client.receive_data(server.data_to_send()).success is True

    client.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, ("0.0.0.0", 0))
    )
    command = server.receive_data(client.data_to_send())
    assert isinstance(command, SOCKS5CommandRequest)
    assert command.command == SOCKS5Command.CONNECT

    reply = SOCKS5Reply(
        reply_code=SOCKS5ReplyCode.SUCCEEDED,
        atype=SOCKS5AType.IPV4_ADDRESS,
        addr="0.0.0.0",
        port=0,
    )
    assert server.send(reply) is None
    client.receive_data(server.data_to_send())
    assert server.state == SOCKS5State.TUNNEL_READY


def test_socks5_server_rejects_username_password_failure() -> None:
    server = SOCKS5ServerConnection()

    assert server.receive_data(b"\x05\x01\x02") == SOCKS5AuthMethodsRequest(
        [SOCKS5AuthMethod.USERNAME_PASSWORD]
    )
    assert server.send(SOCKS5AuthReply(SOCKS5AuthMethod.USERNAME_PASSWORD)) is None
    assert server.data_to_send() == b"\x05\x02"

    assert server.receive_data(b"\x01\x01u\x01p") == (
        SOCKS5UsernamePasswordRequest(b"u", b"p")
    )
    assert server.send(SOCKS5UsernamePasswordReply(success=False)) is None

    assert server.data_to_send() == b"\x01\x01"
    assert server.state == SOCKS5State.MUST_CLOSE


def test_socks5_server_holds_early_command_until_password_decision() -> None:
    server = SOCKS5ServerConnection()
    credentials = b"\x01\x01u\x01p"
    command = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    ).dumps()

    assert server.receive_data(b"\x05\x01\x02") == SOCKS5AuthMethodsRequest(
        [SOCKS5AuthMethod.USERNAME_PASSWORD]
    )
    assert server.send(SOCKS5AuthReply(SOCKS5AuthMethod.USERNAME_PASSWORD)) is None

    event = server.receive_data(credentials + command)
    assert event == SOCKS5UsernamePasswordRequest(b"u", b"p")
    assert server.state == SOCKS5State.SERVER_WAIT_AUTH_DECISION

    authorized_command = server.send(
        SOCKS5UsernamePasswordReply(success=True)
    )
    assert authorized_command == SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    )
    assert server.state == SOCKS5State.SERVER_WAIT_COMMAND_DECISION


def test_socks5_server_holds_early_command_until_no_auth_decision() -> None:
    server = SOCKS5ServerConnection()
    command = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    ).dumps()

    event = server.receive_data(b"\x05\x01\x00" + command)

    assert event == SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED])
    assert server.state == SOCKS5State.SERVER_WAIT_AUTH_METHOD_DECISION

    authorized_command = server.send(SOCKS5AuthReply(SOCKS5AuthMethod.NO_AUTH_REQUIRED))
    assert authorized_command == SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    )
    assert server.state == SOCKS5State.SERVER_WAIT_COMMAND_DECISION


def test_socks5_server_delivers_tunnel_payload_only_after_success() -> None:
    server = SOCKS5ServerConnection()
    command = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    ).dumps()

    assert server.receive_data(b"\x05\x01\x00") == SOCKS5AuthMethodsRequest(
        [SOCKS5AuthMethod.NO_AUTH_REQUIRED]
    )
    assert server.send(SOCKS5AuthReply(SOCKS5AuthMethod.NO_AUTH_REQUIRED)) is None

    event = server.receive_data(command + b"hello")
    assert event == SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    )
    assert server.state == SOCKS5State.SERVER_WAIT_COMMAND_DECISION

    payload = server.send(
        SOCKS5Reply(
            reply_code=SOCKS5ReplyCode.SUCCEEDED,
            atype=SOCKS5AType.IPV4_ADDRESS,
            addr="0.0.0.0",
            port=0,
        )
    )
    assert payload == SOCKS5DataReceived(b"hello")
    assert server.state == SOCKS5State.TUNNEL_READY
    assert server.receive_data(b"") is None


def test_socks5_server_ignores_unselectable_offered_auth_methods() -> None:
    server = SOCKS5ServerConnection()

    event = server.receive_data(b"\x05\x04\x00\x01\x02\x80")

    assert event == SOCKS5AuthMethodsRequest(
        [
            SOCKS5AuthMethod.NO_AUTH_REQUIRED,
            SOCKS5AuthMethod.GSSAPI,
            SOCKS5AuthMethod.USERNAME_PASSWORD,
        ]
    )
    assert server.send(SOCKS5AuthReply(SOCKS5AuthMethod.NO_AUTH_REQUIRED)) is None
    assert server.data_to_send() == b"\x05\x00"


def test_socks5_server_does_not_accept_unnegotiated_auth_or_early_command() -> None:
    server = SOCKS5ServerConnection()
    unnegotiated_auth = b"\x01\x01u\x01p"
    command = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    ).dumps()

    event = server.receive_data(b"\x05\x01\x00" + unnegotiated_auth + command)

    assert event == SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED])
    assert server.state == SOCKS5State.SERVER_WAIT_AUTH_METHOD_DECISION

    with pytest.raises(ProtocolError):
        server.send(SOCKS5AuthReply(SOCKS5AuthMethod.USERNAME_PASSWORD))
    assert server.state == SOCKS5State.MUST_CLOSE

    with pytest.raises(ProtocolError):
        server.receive_data(b"")
    assert server.state == SOCKS5State.MUST_CLOSE


def test_socks5_server_no_acceptable_methods_closes_connection() -> None:
    server = SOCKS5ServerConnection()
    command = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    ).dumps()

    event = server.receive_data(b"\x05\x01\x01" + command)
    assert isinstance(event, SOCKS5AuthMethodsRequest)

    assert server.send(SOCKS5AuthReply(SOCKS5AuthMethod.NO_ACCEPTABLE_METHODS)) is None

    assert server.data_to_send() == b"\x05\xff"
    assert server.state == SOCKS5State.MUST_CLOSE


def test_socks5_server_pending_input_limit_applies_before_authorization() -> None:
    server = SOCKS5ServerConnection(max_pending_input=8)
    command = SOCKS5CommandRequest.from_address(
        SOCKS5Command.CONNECT, "127.0.0.1:1080"
    ).dumps()

    event = server.receive_data(b"\x05\x01\x00" + command)
    assert isinstance(event, SOCKS5AuthMethodsRequest)

    with pytest.raises(ProtocolError, match="Pending input limit"):
        server.send(SOCKS5AuthReply(SOCKS5AuthMethod.NO_AUTH_REQUIRED))
    assert server.state == SOCKS5State.MUST_CLOSE
    assert server.data_to_send() == b""


def test_socks5_server_protocol_error_cannot_recover_to_authenticated_state() -> None:
    server = SOCKS5ServerConnection()

    with pytest.raises(ProtocolError):
        server.receive_data(b"\x04\x01\x00")
    assert server.state == SOCKS5State.MUST_CLOSE

    with pytest.raises(ProtocolError):
        server.receive_data(b"\x05\x01\x00")
    with pytest.raises(ProtocolError):
        server.send(SOCKS5AuthReply(SOCKS5AuthMethod.NO_AUTH_REQUIRED))

    assert server.state == SOCKS5State.MUST_CLOSE


def test_socks5_server_rejects_unsupported_command() -> None:
    server = SOCKS5ServerConnection()
    server.receive_data(b"\x05\x01\x00")
    server.send(SOCKS5AuthReply(SOCKS5AuthMethod.NO_AUTH_REQUIRED))
    assert server.data_to_send() == b"\x05\x00"

    assert (
        server.receive_data(
            b"\x05\x02\x00\x01\x7f\x00\x00\x01\x04\x38"
        )
        is None
    )
    assert server.data_to_send() == b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"
    assert server.state == SOCKS5State.MUST_CLOSE
