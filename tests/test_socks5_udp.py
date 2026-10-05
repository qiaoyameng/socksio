"""Byte vector tests for the SOCKS5 UDP ASSOCIATE sans-I/O path.

No proxy server or network access is required: every wire message is built
from literal bytes.
"""
import socket

import pytest

from socksio import (
    ProtocolError,
    SOCKS5AType,
    SOCKS5AuthMethod,
    SOCKS5AuthMethodsRequest,
    SOCKS5Command,
    SOCKS5CommandRequest,
    SOCKS5Connection,
    SOCKS5Datagram,
    SOCKS5FragmentNotSupportedError,
    SOCKS5ReplyCode,
    SOCKS5UDPAssociation,
    SOCKS5UDPAssociationClosedError,
    SOCKS5UDPNotAssociatedError,
    SOCKS5UnsupportedDatagram,
)
from socksio.socks5 import SOCKS5State

RELAY_ADDRESS = b"\x7f\x00\x00\x01"
RELAY_PORT = 9999
SUCCESSFUL_UDP_REPLY = (
    b"\x05"
    + SOCKS5ReplyCode.SUCCEEDED
    + b"\x00"
    + SOCKS5AType.IPV4_ADDRESS
    + RELAY_ADDRESS
    + RELAY_PORT.to_bytes(2, byteorder="big")
)

IPV4_ADDRESS = b"\x7f\x00\x00\x01"
IPV6_ADDRESS = b"\x00" * 15 + b"\x01"
DOMAIN = b"localhost"
DST_PORT = 3080
PACKED_PORT = DST_PORT.to_bytes(2, byteorder="big")
BINARY_PAYLOAD = bytes(range(256)) + b"\x00\x00\x00\xff\xfe"


@pytest.fixture
def authenticated_conn() -> SOCKS5Connection:
    conn = SOCKS5Connection()
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED]))
    conn.data_to_send()
    conn.receive_data(b"\x05\x00")
    return conn


@pytest.fixture
def udp_associated_conn(authenticated_conn: SOCKS5Connection) -> SOCKS5Connection:
    authenticated_conn.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.UDP_ASSOCIATE, "0.0.0.0:0")
    )
    assert authenticated_conn.data_to_send() == (
        b"\x05\x03\x00\x01" + b"\x00" * 6
    )
    reply = authenticated_conn.receive_data(SUCCESSFUL_UDP_REPLY)
    assert reply.reply_code == SOCKS5ReplyCode.SUCCEEDED
    return authenticated_conn


@pytest.fixture
def udp_association(
    udp_associated_conn: SOCKS5Connection,
) -> SOCKS5UDPAssociation:
    return udp_associated_conn.udp_associate()


def test_successful_udp_associate_records_relay_address(
    udp_associated_conn: SOCKS5Connection,
) -> None:
    assert udp_associated_conn.state == SOCKS5State.TUNNEL_READY
    assert udp_associated_conn.associated_address == ("127.0.0.1", RELAY_PORT)
    association = udp_associated_conn.udp_associate()
    assert association.relay_address == ("127.0.0.1", RELAY_PORT)
    assert udp_associated_conn.udp_associate() is association


def test_udp_associate_requires_successful_command(
    authenticated_conn: SOCKS5Connection,
) -> None:
    with pytest.raises(SOCKS5UDPNotAssociatedError):
        authenticated_conn.udp_associate()


def test_udp_associate_rejects_connect_tunnel(
    authenticated_conn: SOCKS5Connection,
) -> None:
    authenticated_conn.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.CONNECT, "127.0.0.1:1080")
    )
    authenticated_conn.data_to_send()
    authenticated_conn.receive_data(SUCCESSFUL_UDP_REPLY)

    with pytest.raises(SOCKS5UDPNotAssociatedError):
        authenticated_conn.udp_associate()


def test_udp_associate_rejected_reply_closes_connection(
    authenticated_conn: SOCKS5Connection,
) -> None:
    authenticated_conn.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.UDP_ASSOCIATE, "0.0.0.0:0")
    )
    authenticated_conn.data_to_send()
    reply_data = (
        b"\x05"
        + SOCKS5ReplyCode.COMMAND_NOT_SUPPORTED
        + b"\x00"
        + SOCKS5AType.IPV4_ADDRESS
        + b"\x00" * 4
        + b"\x00\x00"
    )
    authenticated_conn.receive_data(reply_data)

    assert authenticated_conn.state == SOCKS5State.MUST_CLOSE
    assert not authenticated_conn.is_open
    with pytest.raises(SOCKS5UDPNotAssociatedError):
        authenticated_conn.udp_associate()


@pytest.mark.parametrize(
    "address,atype,packed_addr",
    [
        ("127.0.0.1:3080", SOCKS5AType.IPV4_ADDRESS, IPV4_ADDRESS),
        ("localhost:3080", SOCKS5AType.DOMAIN_NAME, b"\x09" + DOMAIN),
        ("[0:0:0:0:0:0:0:1]:3080", SOCKS5AType.IPV6_ADDRESS, IPV6_ADDRESS),
    ],
)
def test_datagram_dumps_address_types(
    address: str, atype: SOCKS5AType, packed_addr: bytes
) -> None:
    datagram = SOCKS5Datagram.from_address(address, BINARY_PAYLOAD)
    expected = (
        b"\x00\x00"  # reserved
        + b"\x00"  # FRAG
        + atype
        + packed_addr
        + PACKED_PORT
        + BINARY_PAYLOAD
    )
    assert datagram.dumps() == expected


@pytest.mark.parametrize(
    "atype,packed_addr,expected_addr",
    [
        (SOCKS5AType.IPV4_ADDRESS, IPV4_ADDRESS, b"\x7f\x00\x00\x01"),
        (SOCKS5AType.DOMAIN_NAME, b"\x09" + DOMAIN, b"localhost"),
        (SOCKS5AType.IPV6_ADDRESS, IPV6_ADDRESS, IPV6_ADDRESS),
    ],
)
def test_datagram_loads_address_types_preserves_payload(
    atype: SOCKS5AType, packed_addr: bytes, expected_addr: bytes
) -> None:
    wire = b"\x00\x00\x00" + atype + packed_addr + PACKED_PORT + BINARY_PAYLOAD
    datagram = SOCKS5Datagram.loads(wire)

    assert datagram.atype == atype
    assert datagram.addr == expected_addr
    assert datagram.port == DST_PORT
    assert datagram.data == BINARY_PAYLOAD
    assert datagram.fragment == 0
    assert datagram.last_fragment is True


def test_datagram_roundtrip_empty_payload() -> None:
    datagram = SOCKS5Datagram.from_address("127.0.0.1:3080", b"")
    assert SOCKS5Datagram.loads(datagram.dumps()).data == b""


@pytest.mark.parametrize(
    "data",
    [
        b"",  # empty
        b"\x00",  # too short
        b"\x00\x00\x00",  # missing ATYP
        b"\x00\x00\x00\x01",  # missing address and port
        b"\x00\x01\x00\x01" + IPV4_ADDRESS + PACKED_PORT,  # non-zero reserved
        b"\x01\x00\x00\x01" + IPV4_ADDRESS + PACKED_PORT,  # non-zero reserved
        b"\x00\x00\x00\x09" + IPV4_ADDRESS + PACKED_PORT,  # unknown ATYP
        b"\x00\x00\x00\x01\x7f\x00\x00\x01\x04",  # truncated port, ipv4
        b"\x00\x00\x00\x04" + IPV6_ADDRESS[:-1] + PACKED_PORT,  # truncated ipv6
        b"\x00\x00\x00\x03\x09local",  # truncated domain and missing port
        b"\x00\x00\x00\x03\x09localhost\x04",  # truncated port, domain
    ],
)
def test_datagram_loads_malformed(data: bytes) -> None:
    with pytest.raises(ProtocolError):
        SOCKS5Datagram.loads(data)


def test_datagram_loads_fragment_raises() -> None:
    wire = b"\x00\x00\x01\x01" + IPV4_ADDRESS + PACKED_PORT + b"partial payload"
    with pytest.raises(SOCKS5FragmentNotSupportedError):
        SOCKS5Datagram.loads(wire)


def test_datagram_dumps_fragment_raises() -> None:
    datagram = SOCKS5Datagram.from_address("127.0.0.1:3080", b"x")
    fragmented = datagram._replace(fragment=2, last_fragment=False)
    with pytest.raises(SOCKS5FragmentNotSupportedError):
        fragmented.dumps()


@pytest.mark.parametrize("port", [-1, 65536, 2**16])
def test_datagram_dumps_invalid_port(port: int) -> None:
    datagram = SOCKS5Datagram(
        atype=SOCKS5AType.IPV4_ADDRESS,
        addr=IPV4_ADDRESS,
        port=port,
        data=b"",
    )
    with pytest.raises(Exception):
        datagram.dumps()


def test_datagram_dumps_domain_too_long() -> None:
    datagram = SOCKS5Datagram(
        atype=SOCKS5AType.DOMAIN_NAME,
        addr=b"a" * 256,
        port=53,
        data=b"",
    )
    with pytest.raises(Exception):
        datagram.dumps()


def test_association_send_and_receive(udp_association: SOCKS5UDPAssociation) -> None:
    datagram = SOCKS5Datagram.from_address("example.com:53", BINARY_PAYLOAD)
    udp_association.send(datagram)
    udp_association.send(datagram)

    wire = udp_association.data_to_send()
    expected_single = datagram.dumps()
    assert wire == expected_single * 2
    assert udp_association.data_to_send() == b""

    event = udp_association.receive_data(expected_single)
    assert event == datagram
    assert isinstance(event, SOCKS5Datagram)
    assert event.data == BINARY_PAYLOAD


def test_association_receive_fragment_is_distinct_event(
    udp_association: SOCKS5UDPAssociation,
) -> None:
    wire = b"\x00\x00\x01\x01" + IPV4_ADDRESS + PACKED_PORT + b"partial"
    event = udp_association.receive_data(wire)

    assert isinstance(event, SOCKS5UnsupportedDatagram)
    assert not isinstance(event, SOCKS5Datagram)
    assert event.fragment == 1
    assert event.fragmented is True
    assert event.data == wire


def test_association_send_after_control_close_raises(
    udp_associated_conn: SOCKS5Connection,
    udp_association: SOCKS5UDPAssociation,
) -> None:
    udp_associated_conn.close()
    assert not udp_associated_conn.is_open

    with pytest.raises(SOCKS5UDPAssociationClosedError):
        udp_association.send(SOCKS5Datagram.from_address("127.0.0.1:53", b"x"))
    with pytest.raises(SOCKS5UDPAssociationClosedError):
        udp_association.receive_data(
            b"\x00\x00\x00\x01" + IPV4_ADDRESS + PACKED_PORT + b"x"
        )
    with pytest.raises(SOCKS5UDPNotAssociatedError):
        udp_associated_conn.udp_associate()


def test_association_usable_until_close(udp_association: SOCKS5UDPAssociation) -> None:
    wire = SOCKS5Datagram.from_address("127.0.0.1:53", b"x").dumps()
    assert isinstance(udp_association.receive_data(wire), SOCKS5Datagram)


@pytest.mark.parametrize(
    "peer,expected_addr",
    [
        (("proxy.example", 1080), "proxy.example"),
        ((b"proxy.example", 1080), "proxy.example"),
        ("proxy.example:1080", "proxy.example"),
        (b"proxy.example:1080", "proxy.example"),
        (("10.0.0.1", 1080), "10.0.0.1"),
    ],
)
def test_zero_relay_address_uses_control_peer(
    authenticated_conn: SOCKS5Connection,
    peer,
    expected_addr: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbid_network(*args, **kwargs):
        raise AssertionError("no DNS or network access is allowed")

    monkeypatch.setattr(socket, "getaddrinfo", forbid_network)
    monkeypatch.setattr(socket, "create_connection", forbid_network)

    authenticated_conn.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.UDP_ASSOCIATE, "0.0.0.0:0")
    )
    authenticated_conn.data_to_send()
    authenticated_conn.receive_data(
        b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00\x00"
    )

    with pytest.raises(SOCKS5UDPNotAssociatedError):
        authenticated_conn.udp_associate()

    association = authenticated_conn.udp_associate(peer)
    assert association.relay_address == (expected_addr, 1080)


def test_zero_relay_address_ipv6(authenticated_conn: SOCKS5Connection) -> None:
    authenticated_conn.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.UDP_ASSOCIATE, "0.0.0.0:0")
    )
    authenticated_conn.data_to_send()
    authenticated_conn.receive_data(
        b"\x05\x00\x00\x04" + b"\x00" * 16 + b"\x00\x00"
    )

    association = authenticated_conn.udp_associate("[2001:db8::1]:1080")
    assert association.relay_address == ("2001:db8::1", 1080)
