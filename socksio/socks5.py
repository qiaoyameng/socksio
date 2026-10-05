import enum
import typing
from functools import singledispatchmethod

from ._types import StrOrBytes
from .exceptions import (
    ProtocolError,
    SOCKS5FragmentNotSupportedError,
    SOCKS5UDPAssociationClosedError,
    SOCKS5UDPNotAssociatedError,
    SOCKSError,
)
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

    The UDP request header uses the same address formats as the command
    requests::

        +----+------+------+----------+----------+----------+
        |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        +----+------+------+----------+----------+----------+
        | 2  |  1   |  1   | Variable |    2     | Variable |
        +----+------+------+----------+----------+----------+

    Only complete, unfragmented datagrams (``FRAG == 0``) are supported.

    Args:
        atype: The address type of the addr field.
        addr: Encoded address of the target host, raw IP or raw domain bytes.
        port: The port number of the target host.
        data: The datagram payload, kept as arbitrary binary data.
        fragment: Fragment number, ``0`` for a standalone datagram.
        last_fragment: Whether this datagram is the last of a fragment series.
    """

    atype: SOCKS5AType
    addr: bytes
    port: int
    data: bytes

    fragment: int = 0
    last_fragment: bool = False

    @classmethod
    def from_address(
        cls,
        address: typing.Union[StrOrBytes, typing.Tuple[StrOrBytes, int]],
        data: bytes,
    ) -> "SOCKS5Datagram":
        """Builds a datagram addressed to ``address`` carrying ``data``.

        Args:
            address: A string in the form 'HOST:PORT' or a tuple of address
                string and port number. The address type is inferred from it.
            data: The arbitrary binary payload of the datagram.

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
            last_fragment=True,
        )

    @property
    def packed_addr(self) -> bytes:
        """The address packed in the form required by its address type."""
        if self.atype == SOCKS5AType.IPV4_ADDRESS:
            assert len(self.addr) == 4
            return self.addr
        elif self.atype == SOCKS5AType.IPV6_ADDRESS:
            assert len(self.addr) == 16
            return self.addr
        else:
            length = len(self.addr)
            return length.to_bytes(1, byteorder="big") + self.addr

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5Datagram":
        """Unpacks a UDP datagram into an instance.

        Returns:
            The unpacked datagram instance.

        Raises:
            ProtocolError: If the data does not match the UDP request header
                structure (reserved bytes, ATYP, domain length or port).
            SOCKS5FragmentNotSupportedError: If the FRAG field is non-zero.
                The fragment is never returned as a complete payload.
        """
        if len(data) < 4:
            raise ProtocolError("Malformed datagram")
        if data[0:2] != b"\x00\x00":
            raise ProtocolError("Malformed datagram")

        frag = data[2]
        if frag != 0:
            raise SOCKS5FragmentNotSupportedError(
                f"Fragmented datagrams are not supported (FRAG={frag})"
            )

        try:
            atype = SOCKS5AType(data[3:4])
        except ValueError as exc:
            raise ProtocolError("Malformed datagram") from exc

        if atype == SOCKS5AType.IPV4_ADDRESS:
            if len(data) < 10:
                raise ProtocolError("Malformed datagram")
            addr = data[4:8]
            payload_start = 8
        elif atype == SOCKS5AType.IPV6_ADDRESS:
            if len(data) < 22:
                raise ProtocolError("Malformed datagram")
            addr = data[4:20]
            payload_start = 20
        else:
            if len(data) < 5:
                raise ProtocolError("Malformed datagram")
            domain_length = data[4]
            header_length = 5 + domain_length + 2
            if len(data) < header_length:
                raise ProtocolError("Malformed datagram")
            addr = data[5 : 5 + domain_length]
            payload_start = 5 + domain_length

        port = int.from_bytes(
            data[payload_start : payload_start + 2], byteorder="big"
        )
        payload = data[payload_start + 2 :]

        return cls(
            atype=atype,
            addr=addr,
            port=port,
            data=payload,
            fragment=frag,
            last_fragment=frag == 0,
        )

    def dumps(self) -> bytes:
        """Packs the datagram into the UDP request header plus its payload.

        Returns:
            The packed datagram.

        Raises:
            SOCKS5FragmentNotSupportedError: If the instance describes a
                fragmented datagram.
            SOCKSError: If the port is outside the valid range or a domain is
                longer than the 255 bytes allowed by the length field.
        """
        if self.fragment != 0:
            raise SOCKS5FragmentNotSupportedError(
                "Fragmented datagrams are not supported"
            )
        if not 0 <= self.port <= 0xFFFF:
            raise SOCKSError("Port must be between 0 and 65535")
        if self.atype == SOCKS5AType.DOMAIN_NAME and len(self.addr) > 255:
            raise SOCKSError("Domain name must be at most 255 bytes")

        return b"".join(
            [
                b"\x00\x00",  # reserved
                b"\x00",  # FRAG, standalone datagram
                self.atype,
                self.packed_addr,
                self.port.to_bytes(2, byteorder="big"),
                self.data,
            ]
        )


class SOCKS5UnsupportedDatagram(typing.NamedTuple):
    """Event produced for a datagram that could not be handled.

    The first version only rejects fragmented datagrams (``FRAG != 0``). The
    event is distinct from :class:`SOCKS5Datagram` so the fragment bytes are
    not mistaken for a complete payload.

    Args:
        data: The raw datagram bytes that were rejected.
        fragment: The value of the FRAG field.
    """

    data: bytes
    fragment: int

    @property
    def fragmented(self) -> bool:
        """Whether the datagram was rejected because it was fragmented."""
        return self.fragment != 0


SOCKS5UDPEvent = typing.Union[SOCKS5Datagram, SOCKS5UnsupportedDatagram]


class SOCKS5UDPAssociation:
    """Sans-I/O side of a UDP ASSOCIATE relay.

    Instances are normally created from the control connection with
    :meth:`SOCKS5Connection.udp_associate` once the UDP ASSOCIATE command has
    succeeded. They encode outgoing datagrams and decode datagrams received
    from the relay while the control connection stays alive.

    Args:
        relay_addr: Address of the UDP relay the caller must send datagrams
            to and receive them from.
        relay_port: Port of the UDP relay.
        control_connection: The control connection used to establish the
            association. Datagrams are no longer accepted once it is closed.
    """

    def __init__(
        self,
        relay_addr: str,
        relay_port: int,
        control_connection: "SOCKS5Connection",
    ) -> None:
        self.relay_addr = relay_addr
        self.relay_port = relay_port
        self._connection = control_connection
        self._data_to_send = bytearray()

    @property
    def relay_address(self) -> typing.Tuple[str, int]:
        """The (addr, port) tuple of the UDP relay."""
        return self.relay_addr, self.relay_port

    def _require_open_association(self) -> None:
        if not self._connection.is_open:
            raise SOCKS5UDPAssociationClosedError(
                "Cannot use a UDP association after the control connection "
                "has been closed"
            )

    def send(self, datagram: SOCKS5Datagram) -> None:
        """Packs a datagram and adds it to the send data buffer.

        Args:
            datagram: The datagram to be sent through the relay.

        Raises:
            SOCKS5UDPAssociationClosedError: If the control connection is no
                longer open.
        """
        self._require_open_association()
        self._data_to_send += datagram.dumps()

    def receive_data(self, data: bytes) -> SOCKS5UDPEvent:
        """Unpacks data received from the UDP relay.

        Args:
            data: The raw datagram bytes received from the relay.

        Returns:
            A :class:`SOCKS5Datagram` for complete datagrams or a
            :class:`SOCKS5UnsupportedDatagram` for unsupported ones.

        Raises:
            SOCKS5UDPAssociationClosedError: If the control connection is no
                longer open.
            ProtocolError: If the data does not conform to the structure.
        """
        self._require_open_association()
        try:
            return SOCKS5Datagram.loads(data)
        except SOCKS5FragmentNotSupportedError:  # first version: no fragments
            return SOCKS5UnsupportedDatagram(data=data, fragment=data[2])

    def data_to_send(self) -> bytes:
        """Returns the buffered encoded datagrams and clears the buffer."""
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data


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
        self._last_command: typing.Optional[SOCKS5Command] = None
        self.associated_address: typing.Optional[typing.Tuple[str, int]] = None
        self._udp_association: typing.Optional[SOCKS5UDPAssociation] = None

    @property
    def state(self) -> SOCKS5State:
        """Returns the current state of the protocol."""
        return self._state

    @property
    def is_open(self) -> bool:
        """Whether the control connection can still be used.

        A connection that must be closed because of a failed command or that
        has been explicitly closed can no longer be used, including for UDP
        associations created from it.
        """
        return self._state != SOCKS5State.MUST_CLOSE

    def close(self) -> None:
        """Marks the control connection as closed.

        Any UDP association established through this connection stops
        accepting datagrams afterwards.
        """
        self._state = SOCKS5State.MUST_CLOSE

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
        self._last_command = request.command
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
                if self._last_command == SOCKS5Command.UDP_ASSOCIATE:
                    self.associated_address = (reply.addr, reply.port)
            else:
                self._state = SOCKS5State.MUST_CLOSE

            return reply

        raise NotImplementedError()  # pragma: nocover

    def udp_associate(
        self,
        control_peer: typing.Optional[
            typing.Union[StrOrBytes, typing.Tuple[StrOrBytes, int]]
        ] = None,
    ) -> SOCKS5UDPAssociation:
        """Creates the UDP association after a successful UDP ASSOCIATE reply.

        The relay address is taken from the proxy's reply. Per RFC 1928 a
        reply with an all-zero address (``0.0.0.0`` and port ``0``) means the
        client should send datagrams to the control connection's peer. In that
        case the caller must provide that peer explicitly via ``control_peer``;
        this method never performs DNS resolution or any network access.

        Args:
            control_peer: Peer of the control connection, as a
                ``(address, port)`` tuple or an ``'address:port'`` string.
                Required when the relay returned an all-zero address, ignored
                otherwise.

        Returns:
            The ready to use :class:`SOCKS5UDPAssociation`.

        Raises:
            SOCKS5UDPNotAssociatedError: If the tunnel is not ready, the last
                command was not UDP ASSOCIATE, the control connection is
                closed or the reply address is all-zero without a
                ``control_peer``.
        """
        if not self.is_open:
            raise SOCKS5UDPNotAssociatedError(
                "Cannot create a UDP association on a closed control connection"
            )
        if self._state != SOCKS5State.TUNNEL_READY:
            raise SOCKS5UDPNotAssociatedError(
                "Cannot create a UDP association before a successful UDP "
                "ASSOCIATE reply"
            )
        if self._last_command != SOCKS5Command.UDP_ASSOCIATE:
            raise SOCKS5UDPNotAssociatedError(
                "The last command was not UDP ASSOCIATE"
            )

        if self._udp_association is not None:
            return self._udp_association

        assert self.associated_address is not None
        relay_addr, relay_port = self.associated_address
        if relay_addr in ("0.0.0.0", "::") and relay_port == 0:
            if control_peer is None:
                raise SOCKS5UDPNotAssociatedError(
                    "The proxy returned an all-zero relay address, the control "
                    "connection peer must be provided"
                )
            peer_addr, peer_port = get_address_port_tuple_from_address(control_peer)
            relay_addr, relay_port = peer_addr, peer_port

        self._udp_association = SOCKS5UDPAssociation(
            relay_addr=relay_addr,
            relay_port=relay_port,
            control_connection=self,
        )
        return self._udp_association

    def data_to_send(self) -> bytes:
        """Returns the data to be sent via the I/O library of choice.

        Also clears the connection's buffer.
        """
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data
