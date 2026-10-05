import enum
import typing
from functools import singledispatchmethod

from ._types import StrOrBytes
from .exceptions import FragmentationNotSupported, ProtocolError, SOCKSError
from .utils import (
    AddressType,
    decode_address,
    encode_address,
    get_address_port_tuple_from_address,
)


class SOCKS5AuthMethod(bytes, enum.Enum):
    """Enumeration of SOCKS5 authentication methods."""

    NO_AUTH_REQUIRED = b"\x00"
    GSSAPI = b"\x01"
    USERNAME_PASSWORD = b"\x02"
    NO_ACCEPTABLE_METHODS = b"\xff"


class SOCKS5Command(bytes, enum.Enum):
    """Enumeration of SOCKS5 commands."""

    CONNECT = b"\x01"
    BIND = b"\x02"
    UDP_ASSOCIATE = b"\x03"


class SOCKS5AType(bytes, enum.Enum):
    """Enumeration of SOCKS5 address types."""

    IPV4_ADDRESS = b"\x01"
    DOMAIN_NAME = b"\x03"
    IPV6_ADDRESS = b"\x04"

    @classmethod
    def from_atype(cls, atype: AddressType) -> "SOCKS5AType":
        if atype == AddressType.IPV4:
            return SOCKS5AType.IPV4_ADDRESS
        elif atype == AddressType.DN:
            return SOCKS5AType.DOMAIN_NAME
        elif atype == AddressType.IPV6:
            return SOCKS5AType.IPV6_ADDRESS
        raise ValueError(atype)


class SOCKS5ReplyCode(bytes, enum.Enum):
    """Enumeration of SOCKS5 reply codes."""

    SUCCEEDED = b"\x00"
    GENERAL_SERVER_FAILURE = b"\x01"
    CONNECTION_NOT_ALLOWED_BY_RULESET = b"\x02"
    NETWORK_UNREACHABLE = b"\x03"
    HOST_UNREACHABLE = b"\x04"
    CONNECTION_REFUSED = b"\x05"
    TTL_EXPIRED = b"\x06"
    COMMAND_NOT_SUPPORTED = b"\x07"
    ADDRESS_TYPE_NOT_SUPPORTED = b"\x08"


class SOCKS5AuthMethodsRequest(typing.NamedTuple):
    """Encapsulates a request to the proxy for available authentication methods.

    Args:
        methods: A list of acceptable authentication methods.
    """

    methods: typing.List[SOCKS5AuthMethod]

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form."""

        return b"".join(
            [
                b"\x05",
                len(self.methods).to_bytes(1, byteorder="big"),
                b"".join(self.methods),
            ]
        )


class SOCKS5AuthReply(typing.NamedTuple):
    """Encapsulates a reply from the proxy with the authentication method to be used.

    Args:
        method: The authentication method to be used.

    Raises:
        ProtocolError: If the data does not conform with the expected structure.
    """

    method: SOCKS5AuthMethod

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5AuthReply":
        """Unpacks the authentication reply data into an instance.

        Returns:
            The unpacked authentication reply instance.

        Raises:
            ProtocolError: If the data does not match the spec.
        """
        if len(data) != 2:
            raise ProtocolError("Malformed reply")

        try:
            return cls(method=SOCKS5AuthMethod(data[1:2]))
        except ValueError as exc:
            raise ProtocolError("Malformed reply") from exc


class SOCKS5UsernamePasswordRequest(typing.NamedTuple):
    """Encapsulates a username/password authentication request to the proxy server."""

    username: bytes
    password: bytes

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form.

        Returns:
            The packed request.
        """
        return b"".join(
            [
                b"\x01",
                len(self.username).to_bytes(1, byteorder="big"),
                self.username,
                len(self.password).to_bytes(1, byteorder="big"),
                self.password,
            ]
        )


class SOCKS5UsernamePasswordReply(typing.NamedTuple):
    """Encapsulates a username/password authentication reply from the proxy server."""

    success: bool

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5UsernamePasswordReply":
        """Unpacks the reply authentication data into an instance.

        Returns:
            The unpacked authentication reply instance.
        """
        return cls(success=data == b"\x01\x00")


class SOCKS5CommandRequest(typing.NamedTuple):
    """Encapsulates a command request to the proxy server.

    Args:
        command: The command to request.
        atype: The address type of the addr field.
        addr: Address of the target host.
        port: The port number to connect to on the target host.
    """

    command: SOCKS5Command
    atype: SOCKS5AType
    addr: bytes
    port: int

    @classmethod
    def from_address(
        cls,
        command: SOCKS5Command,
        address: typing.Union[StrOrBytes, typing.Tuple[StrOrBytes, int]],
    ) -> "SOCKS5CommandRequest":
        """Convenience class method to build an instance from command and address.

        Args:
            command: The command to request.
            address: A string in the form 'HOST:PORT' or a tuple of ip address string
                and port number. The address type will be inferred.

        Returns:
            A SOCKS5CommandRequest instance.

        Raises:
            SOCKSError: If a domain name or IPv6 address was supplied.
        """
        address, port = get_address_port_tuple_from_address(address)
        atype, encoded_addr = encode_address(address)
        return cls(
            command=command,
            atype=SOCKS5AType.from_atype(atype),
            addr=encoded_addr,
            port=port,
        )

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form.

        Returns:
            The packed request.
        """
        return b"".join(
            [
                b"\x05",
                self.command,
                b"\x00",
                self.atype,
                self.packed_addr,
                (self.port).to_bytes(2, byteorder="big"),
            ]
        )

    @property
    def packed_addr(self) -> bytes:
        """Property returning the packed address in the correct form for its type."""
        if self.atype == SOCKS5AType.IPV4_ADDRESS:
            assert len(self.addr) == 4
            return self.addr
        elif self.atype == SOCKS5AType.IPV6_ADDRESS:
            assert len(self.addr) == 16
            return self.addr
        else:
            length = len(self.addr)
            return length.to_bytes(1, byteorder="big") + self.addr


class SOCKS5Reply(typing.NamedTuple):
    """Encapsulates a reply from the SOCKS5 proxy server

    Args:
        reply_code: The code representing the type of reply.
        atype: The address type of the addr field.
        addr: Optional IP address returned.
        port: The port number returned.
    """

    reply_code: SOCKS5ReplyCode
    atype: SOCKS5AType
    addr: str
    port: int

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5Reply":
        """Unpacks the reply data into an instance.

        Returns:
            The unpacked reply instance.

        Raises:
            ProtocolError: If the data does not match the spec.
        """
        if data[0:1] != b"\x05":
            raise ProtocolError("Malformed reply")

        try:
            atype = SOCKS5AType(data[3:4])

            return cls(
                reply_code=SOCKS5ReplyCode(data[1:2]),
                atype=atype,
                addr=decode_address(AddressType.from_socks5_atype(atype), data[4:-2]),
                port=int.from_bytes(data[-2:], byteorder="big"),
            )
        except ValueError as exc:
            raise ProtocolError("Malformed reply") from exc


class SOCKS5Datagram(typing.NamedTuple):
    """Encapsulates a SOCKS5 datagram for UDP connections.

    Args:
        atype: The address type of the addr field.
        addr: The encoded address of the destination host.
        port: The port number of the destination host.
        data: The payload, preserved as arbitrary binary data.
        fragment: The fragment number. Fragmentation is not supported,
            so this must always be zero.
        last_fragment: Whether this is the last fragment. Always true
            since fragmentation is not supported.

    Raises:
        ProtocolError: If the data does not conform with the expected structure.
        FragmentationNotSupported: If the datagram is a fragment.
    """

    atype: SOCKS5AType
    addr: bytes
    port: int
    data: bytes

    fragment: int = 0
    last_fragment: bool = True

    @classmethod
    def from_address(
        cls,
        address: typing.Union[StrOrBytes, typing.Tuple[StrOrBytes, int]],
        data: bytes,
    ) -> "SOCKS5Datagram":
        """Convenience class method to build an instance from address and data.

        Args:
            address: A string in the form 'HOST:PORT' or a tuple of address
                and port number. The address type will be inferred.
            data: The payload to send, kept as arbitrary binary data.

        Returns:
            A SOCKS5Datagram instance.
        """
        address, port = get_address_port_tuple_from_address(address)
        atype, encoded_addr = encode_address(address)
        return cls(
            atype=SOCKS5AType.from_atype(atype),
            addr=encoded_addr,
            port=port,
            data=data,
        )

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5Datagram":
        """Unpacks the datagram data into an instance.

        Returns:
            The unpacked datagram instance.

        Raises:
            ProtocolError: If the data does not match the spec.
            FragmentationNotSupported: If the FRAG field is non-zero.
        """
        if len(data) < 4:
            raise ProtocolError("Malformed datagram")
        if data[0:2] != b"\x00\x00":
            raise ProtocolError("Malformed datagram: reserved bytes must be zero")

        fragment = data[2]
        if fragment != 0:
            raise FragmentationNotSupported(
                "Fragmented UDP datagrams are not supported"
            )

        try:
            atype = SOCKS5AType(data[3:4])
        except ValueError as exc:
            raise ProtocolError("Malformed datagram: invalid address type") from exc

        if atype == SOCKS5AType.IPV4_ADDRESS:
            addr_offset, addr_length = 4, 4
        elif atype == SOCKS5AType.IPV6_ADDRESS:
            addr_offset, addr_length = 4, 16
        else:
            if len(data) < 5:
                raise ProtocolError("Malformed datagram: missing domain length")
            addr_offset, addr_length = 5, data[4]

        addr_end = addr_offset + addr_length
        if len(data) < addr_end + 2:
            raise ProtocolError("Malformed datagram: truncated address or port")

        return cls(
            atype=atype,
            addr=data[addr_offset:addr_end],
            port=int.from_bytes(data[addr_end : addr_end + 2], byteorder="big"),
            data=data[addr_end + 2 :],
        )

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form.

        Returns:
            The packed datagram.

        Raises:
            FragmentationNotSupported: If the fragment number is non-zero.
            ValueError: If the port is out of range or the domain name is
                too long to be encoded.
        """
        if self.fragment != 0:
            raise FragmentationNotSupported(
                "Fragmented UDP datagrams are not supported"
            )
        if not 0 <= self.port <= 65535:
            raise ValueError(f"Port {self.port} out of range (0-65535)")
        return b"".join(
            [
                b"\x00\x00",
                bytes([self.fragment]),
                self.atype,
                self.packed_addr,
                self.port.to_bytes(2, byteorder="big"),
                self.data,
            ]
        )

    @property
    def packed_addr(self) -> bytes:
        """Property returning the packed address in the correct form for its type."""
        if self.atype == SOCKS5AType.IPV4_ADDRESS:
            if len(self.addr) != 4:
                raise ValueError("IPv4 addresses must be 4 bytes long")
            return self.addr
        elif self.atype == SOCKS5AType.IPV6_ADDRESS:
            if len(self.addr) != 16:
                raise ValueError("IPv6 addresses must be 16 bytes long")
            return self.addr
        else:
            length = len(self.addr)
            if length > 255:
                raise ValueError("Domain names longer than 255 bytes are not supported")
            return length.to_bytes(1, byteorder="big") + self.addr


class SOCKS5UDPAssociation:
    """Tracks the state of a UDP ASSOCIATE session (Sans-I/O).

    The association is established over an authenticated SOCKS5 control
    connection by sending a ``SOCKS5CommandRequest`` with the
    ``UDP_ASSOCIATE`` command and building an instance from the reply.
    It records the relay address datagrams should be exchanged with and
    encodes/decodes datagrams without performing any I/O, DNS resolution,
    or network access of its own.

    Once the control connection fails or is closed, ``close()`` must be
    called; a closed association no longer accepts datagrams.
    """

    def __init__(self, relay_addr: str, relay_port: int) -> None:
        self._relay_addr = relay_addr
        self._relay_port = relay_port
        self._closed = False

    @classmethod
    def from_reply(
        cls,
        reply: SOCKS5Reply,
        control_peer: typing.Optional[typing.Tuple[StrOrBytes, int]] = None,
    ) -> "SOCKS5UDPAssociation":
        """Builds an association from the reply to a UDP ASSOCIATE request.

        Args:
            reply: The reply received on the control connection.
            control_peer: Optional (address, port) of the proxy end of the
                control connection. Used as the relay destination when the
                reply carries an all-zero address. It is used as given; no
                DNS resolution or network access is performed.

        Returns:
            A SOCKS5UDPAssociation instance.

        Raises:
            SOCKSError: If the reply reports a failure, or if the reply
                carries an all-zero address and no control connection peer
                was supplied.
        """
        if reply.reply_code != SOCKS5ReplyCode.SUCCEEDED:
            raise SOCKSError(
                f"UDP ASSOCIATE request failed: {reply.reply_code.name}"
            )
        relay_addr = reply.addr
        if relay_addr in ("0.0.0.0", "::"):
            if control_peer is None:
                raise SOCKSError(
                    "Proxy returned an all-zero relay address; the control "
                    "connection peer is required to determine the destination"
                )
            peer_addr = control_peer[0]
            relay_addr = (
                peer_addr.decode() if isinstance(peer_addr, bytes) else peer_addr
            )
        return cls(relay_addr=relay_addr, relay_port=reply.port)

    @property
    def relay_address(self) -> typing.Tuple[str, int]:
        """Returns the (address, port) of the UDP relay."""
        return self._relay_addr, self._relay_port

    @property
    def closed(self) -> bool:
        """Returns whether the association has been closed."""
        return self._closed

    def close(self) -> None:
        """Marks the association as closed.

        Must be called when the control connection fails or is closed.
        """
        self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise SOCKSError(
                "The UDP association is closed; the control connection "
                "failed or was closed"
            )

    def send_datagram(self, datagram: SOCKS5Datagram) -> bytes:
        """Packs a datagram for delivery to the relay.

        Returns:
            The packed datagram to send via the I/O library of choice.

        Raises:
            SOCKSError: If the association is closed.
        """
        self._ensure_open()
        return datagram.dumps()

    def receive_datagram(self, data: bytes) -> SOCKS5Datagram:
        """Unpacks datagram data received from the relay.

        Returns:
            The unpacked datagram instance.

        Raises:
            SOCKSError: If the association is closed.
            ProtocolError: If the data does not match the spec.
            FragmentationNotSupported: If the datagram is a fragment.
        """
        self._ensure_open()
        return SOCKS5Datagram.loads(data)


class SOCKS5State(enum.IntEnum):
    """Enumeration of SOCKS5 protocol states."""

    CLIENT_AUTH_REQUIRED = 1
    SERVER_AUTH_REPLY = 2
    CLIENT_AUTHENTICATED = 3
    TUNNEL_READY = 4
    CLIENT_WAITING_FOR_USERNAME_PASSWORD = 5
    SERVER_VERIFY_USERNAME_PASSWORD = 6
    MUST_CLOSE = 7


SOCKS5RequestType = typing.Union[SOCKS5AuthMethodsRequest, SOCKS5CommandRequest]


class SOCKS5Connection:
    """Encapsulates a SOCKS5 connection.

    Packs request objects into data suitable to be send and unpacks reply
    data into their appropriate reply objects.
    """

    def __init__(self) -> None:
        self._data_to_send = bytearray()
        self._received_data = bytearray()
        self._state = SOCKS5State.CLIENT_AUTH_REQUIRED

    @property
    def state(self) -> SOCKS5State:
        """Returns the current state of the protocol."""
        return self._state

    @singledispatchmethod
    def send(self, request: SOCKS5RequestType) -> None:
        """Packs a request object and adds it to the send data buffer.

        Also progresses the protocol state of the connection.

        Args:
            request: The request instance to be packed.
        """
        raise NotImplementedError()  # pragma: nocover

    @send.register(SOCKS5AuthMethodsRequest)
    def _auth_methods(self, request: SOCKS5AuthMethodsRequest) -> None:
        self._data_to_send += request.dumps()
        self._state = SOCKS5State.SERVER_AUTH_REPLY

    @send.register(SOCKS5UsernamePasswordRequest)
    def _auth_username_password(self, request: SOCKS5UsernamePasswordRequest) -> None:
        if self._state != SOCKS5State.CLIENT_WAITING_FOR_USERNAME_PASSWORD:
            raise ProtocolError("Not currently waiting for username and password")
        self._state = SOCKS5State.SERVER_VERIFY_USERNAME_PASSWORD
        self._data_to_send += request.dumps()

    @send.register(SOCKS5CommandRequest)
    def _command(self, request: SOCKS5CommandRequest) -> None:
        if self._state < SOCKS5State.CLIENT_AUTHENTICATED:
            raise ProtocolError(
                "SOCKS5 connections must be authenticated before sending a request"
            )
        self._data_to_send += request.dumps()

    def receive_data(
        self, data: bytes
    ) -> typing.Union[SOCKS5AuthReply, SOCKS5Reply, SOCKS5UsernamePasswordReply]:
        """Unpacks response data into a reply object.

        Args:
            data: The raw response data from the proxy server.

        Returns:
            A reply instance corresponding to the connection state and reply data.
        """
        if self._state == SOCKS5State.SERVER_AUTH_REPLY:
            auth_reply = SOCKS5AuthReply.loads(data)
            if auth_reply.method == SOCKS5AuthMethod.USERNAME_PASSWORD:
                self._state = SOCKS5State.CLIENT_WAITING_FOR_USERNAME_PASSWORD
            elif auth_reply.method == SOCKS5AuthMethod.NO_AUTH_REQUIRED:
                self._state = SOCKS5State.CLIENT_AUTHENTICATED
            return auth_reply

        if self._state == SOCKS5State.SERVER_VERIFY_USERNAME_PASSWORD:
            username_password_reply = SOCKS5UsernamePasswordReply.loads(data)
            if username_password_reply.success:
                self._state = SOCKS5State.CLIENT_AUTHENTICATED
            else:
                self._state = SOCKS5State.MUST_CLOSE
            return username_password_reply

        if self._state == SOCKS5State.CLIENT_AUTHENTICATED:
            reply = SOCKS5Reply.loads(data)
            if reply.reply_code == SOCKS5ReplyCode.SUCCEEDED:
                self._state = SOCKS5State.TUNNEL_READY
            else:
                self._state = SOCKS5State.MUST_CLOSE

            return reply

        raise NotImplementedError()  # pragma: nocover

    def data_to_send(self) -> bytes:
        """Returns the data to be sent via the I/O library of choice.

        Also clears the connection's buffer.
        """
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data
