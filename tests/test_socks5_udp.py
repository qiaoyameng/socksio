import pytest

from socksio import (
    FragmentationNotSupported,
    ProtocolError,
    SOCKS5AType,
    SOCKS5AuthMethod,
    SOCKS5AuthMethodsRequest,
    SOCKS5Command,
    SOCKS5CommandRequest,
    SOCKS5Connection,
    SOCKS5Datagram,
    SOCKS5ReplyCode,
    SOCKS5UDPAssociation,
    SOCKSError,
)
from socksio.socks5 import SOCKS5State

PAYLOAD = b"\x00\xff\x10binary payload\x00"

IPV4_DATAGRAM = b"\x00\x00\x00\x01\x7f\x00\x00\x01\x0c\x08" + PAYLOAD
IPV6_DATAGRAM = b"\x00\x00\x00\x04" + b"\x00" * 15 + b"\x01" + b"\x0c\x08" + PAYLOAD
DOMAIN_DATAGRAM = b"\x00\x00\x00\x03\x0bexample.com\x0c\x08" + PAYLOAD


@pytest.mark.parametrize(
    "data,expected_atype,expected_addr",
    [
        (IPV4_DATAGRAM, SOCKS5AType.IPV4_ADDRESS, b"\x7f\x00\x00\x01"),
        (IPV6_DATAGRAM, SOCKS5AType.IPV6_ADDRESS, b"\x00" * 15 + b"\x01"),
        (DOMAIN_DATAGRAM, SOCKS5AType.DOMAIN_NAME, b"example.com"),
    ],
)
def test_socks5datagram_loads(data, expected_atype, expected_addr) -> None:
    datagram = SOCKS5Datagram.loads(data)

    assert datagram.atype == expected_atype
    assert datagram.addr == expected_addr
    assert datagram.port == 3080
    assert datagram.data == PAYLOAD
    assert datagram.fragment == 0
    assert datagram.last_fragment is True


@pytest.mark.parametrize("data", [IPV4_DATAGRAM, IPV6_DATAGRAM, DOMAIN_DATAGRAM])
def test_socks5datagram_roundtrip(data) -> None:
    assert SOCKS5Datagram.loads(data).dumps() == data


@pytest.mark.parametrize(
    "address,expected",
    [
        ("127.0.0.1:3080", IPV4_DATAGRAM),
        (("127.0.0.1", 3080), IPV4_DATAGRAM),
        ("[0:0:0:0:0:0:0:1]:3080", IPV6_DATAGRAM),
        ("example.com:3080", DOMAIN_DATAGRAM),
    ],
)
def test_socks5datagram_from_address(address, expected) -> None:
    datagram = SOCKS5Datagram.from_address(address, PAYLOAD)

    assert datagram.dumps() == expected


def test_socks5datagram_loads_non_zero_reserved_bytes() -> None:
    with pytest.raises(ProtocolError):
        SOCKS5Datagram.loads(b"\x00\x01\x00\x01\x7f\x00\x00\x01\x0c\x08" + PAYLOAD)


def test_socks5datagram_loads_invalid_atyp() -> None:
    with pytest.raises(ProtocolError):
        SOCKS5Datagram.loads(b"\x00\x00\x00\x02\x7f\x00\x00\x01\x0c\x08" + PAYLOAD)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00\x00\x00",
        b"\x00\x00\x00\x01\x7f\x00\x00",  # truncated IPv4 address
        b"\x00\x00\x00\x01\x7f\x00\x00\x01\x0c",  # truncated port
        b"\x00\x00\x00\x04" + b"\x00" * 10,  # truncated IPv6 address
        b"\x00\x00\x00\x03",  # missing domain length
        b"\x00\x00\x00\x03\x0bexample.c",  # domain shorter than length byte
        b"\x00\x00\x00\x03\x0bexample.com\x0c",  # truncated port after domain
    ],
)
def test_socks5datagram_loads_malformed(data) -> None:
    with pytest.raises(ProtocolError):
        SOCKS5Datagram.loads(data)


def test_socks5datagram_loads_fragment_not_supported() -> None:
    data = b"\x00\x00\x01\x01\x7f\x00\x00\x01\x0c\x08" + PAYLOAD
    with pytest.raises(FragmentationNotSupported):
        SOCKS5Datagram.loads(data)


def test_fragmentation_not_supported_is_distinguishable_from_protocol_error() -> None:
    assert not issubclass(FragmentationNotSupported, ProtocolError)
    assert issubclass(FragmentationNotSupported, SOCKSError)


def test_socks5datagram_dumps_fragment_not_supported() -> None:
    datagram = SOCKS5Datagram(
        atype=SOCKS5AType.IPV4_ADDRESS,
        addr=b"\x7f\x00\x00\x01",
        port=3080,
        data=PAYLOAD,
        fragment=1,
        last_fragment=False,
    )
    with pytest.raises(FragmentationNotSupported):
        datagram.dumps()


@pytest.mark.parametrize("port", [-1, 65536])
def test_socks5datagram_dumps_port_out_of_range(port) -> None:
    datagram = SOCKS5Datagram(
        atype=SOCKS5AType.IPV4_ADDRESS,
        addr=b"\x7f\x00\x00\x01",
        port=port,
        data=PAYLOAD,
    )
    with pytest.raises(ValueError):
        datagram.dumps()


def test_socks5datagram_dumps_domain_name_too_long() -> None:
    datagram = SOCKS5Datagram(
        atype=SOCKS5AType.DOMAIN_NAME,
        addr=b"a" * 256,
        port=3080,
        data=PAYLOAD,
    )
    with pytest.raises(ValueError):
        datagram.dumps()


def make_udp_associate_reply(
    addr: bytes = b"\x7f\x00\x00\x01",
    atype: bytes = b"\x01",
    port: int = 3080,
    reply_code: bytes = b"\x00",
) -> bytes:
    return b"\x05" + reply_code + b"\x00" + atype + addr + port.to_bytes(2, "big")


def establish_association(reply: bytes, control_peer=None) -> SOCKS5UDPAssociation:
    conn = SOCKS5Connection()
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED]))
    conn.data_to_send()
    conn.receive_data(b"\x05" + SOCKS5AuthMethod.NO_AUTH_REQUIRED)

    request = SOCKS5CommandRequest.from_address(
        SOCKS5Command.UDP_ASSOCIATE, "0.0.0.0:0"
    )
    conn.send(request)
    assert conn.data_to_send() == b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"

    reply_obj = conn.receive_data(reply)
    return SOCKS5UDPAssociation.from_reply(reply_obj, control_peer=control_peer)


def test_udp_associate_records_relay_address() -> None:
    association = establish_association(make_udp_associate_reply())

    assert association.relay_address == ("127.0.0.1", 3080)
    assert association.closed is False


def test_udp_associate_zero_address_uses_control_peer() -> None:
    association = establish_association(
        make_udp_associate_reply(addr=b"\x00\x00\x00\x00"),
        control_peer=("proxy.example.com", 1080),
    )

    assert association.relay_address == ("proxy.example.com", 3080)


def test_udp_associate_zero_ipv6_address_uses_control_peer() -> None:
    association = establish_association(
        make_udp_associate_reply(addr=b"\x00" * 16, atype=b"\x04"),
        control_peer=(b"203.0.113.10", 1080),
    )

    assert association.relay_address == ("203.0.113.10", 3080)


def test_udp_associate_zero_address_without_control_peer_raises() -> None:
    with pytest.raises(SOCKSError):
        establish_association(make_udp_associate_reply(addr=b"\x00" * 4))


def test_udp_associate_failure_reply_raises() -> None:
    conn = SOCKS5Connection()
    conn.send(SOCKS5AuthMethodsRequest([SOCKS5AuthMethod.NO_AUTH_REQUIRED]))
    conn.receive_data(b"\x05" + SOCKS5AuthMethod.NO_AUTH_REQUIRED)
    conn.send(
        SOCKS5CommandRequest.from_address(SOCKS5Command.UDP_ASSOCIATE, "0.0.0.0:0")
    )
    reply = conn.receive_data(
        make_udp_associate_reply(reply_code=SOCKS5ReplyCode.GENERAL_SERVER_FAILURE)
    )

    assert conn.state == SOCKS5State.MUST_CLOSE
    with pytest.raises(SOCKSError):
        SOCKS5UDPAssociation.from_reply(reply)


def test_udp_association_send_and_receive_datagram() -> None:
    association = establish_association(make_udp_associate_reply())

    datagram = SOCKS5Datagram.from_address("example.com:3080", PAYLOAD)
    assert association.send_datagram(datagram) == DOMAIN_DATAGRAM

    received = association.receive_datagram(IPV4_DATAGRAM)
    assert received.addr == b"\x7f\x00\x00\x01"
    assert received.data == PAYLOAD


def test_udp_association_receive_fragment_not_supported() -> None:
    association = establish_association(make_udp_associate_reply())

    with pytest.raises(FragmentationNotSupported):
        fragment = b"\x00\x00\x02\x01\x7f\x00\x00\x01\x0c\x08" + PAYLOAD
        association.receive_datagram(fragment)


def test_udp_association_closed_rejects_datagrams() -> None:
    association = establish_association(make_udp_associate_reply())
    association.close()

    assert association.closed is True
    datagram = SOCKS5Datagram.from_address("127.0.0.1:3080", PAYLOAD)
    with pytest.raises(SOCKSError):
        association.send_datagram(datagram)
    with pytest.raises(SOCKSError):
        association.receive_datagram(IPV4_DATAGRAM)
