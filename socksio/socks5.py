import enum
import socket
import typing
from functools import singledispatchmethod

from ._types import StrOrBytes
from .exceptions import ProtocolError
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

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form.

        Returns:
            The packed reply.
        """
        return b"\x05" + self.method


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

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form.

        Returns:
            The packed reply.
        """
        return b"\x01" + (b"\x00" if self.success else b"\x01")


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

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form.

        Returns:
            The packed reply.
        """
        if self.atype == SOCKS5AType.IPV4_ADDRESS:
            packed_addr = socket.inet_pton(socket.AF_INET, self.addr)
        elif self.atype == SOCKS5AType.IPV6_ADDRESS:
            packed_addr = socket.inet_pton(socket.AF_INET6, self.addr)
        else:
            encoded_addr = self.addr.encode()
            packed_addr = len(encoded_addr).to_bytes(1, byteorder="big") + encoded_addr

        return b"".join(
            [
                b"\x05",
                self.reply_code,
                b"\x00",
                self.atype,
                packed_addr,
                (self.port).to_bytes(2, byteorder="big"),
            ]
        )


class SOCKS5Datagram(typing.NamedTuple):
    """Encapsulates a SOCKS5 datagram for UDP connections.

    Currently not implemented.
    """

    atype: SOCKS5AType
    addr: bytes
    port: int
    data: bytes

    fragment: int
    last_fragment: bool

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5Datagram":
        raise NotImplementedError()  # pragma: nocover

    def dumps(self) -> bytes:
        raise NotImplementedError()  # pragma: nocover


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


class SOCKS5ServerState(enum.IntEnum):
    """Enumeration of SOCKS5 server-side protocol states."""

    WAITING_FOR_AUTH_METHODS = 1
    WAITING_FOR_AUTH_METHOD_DECISION = 2
    WAITING_FOR_USERNAME_PASSWORD = 3
    WAITING_FOR_USERNAME_PASSWORD_DECISION = 4
    WAITING_FOR_COMMAND = 5
    WAITING_FOR_COMMAND_DECISION = 6
    TUNNEL_READY = 7
    CLOSED = 8


class SOCKS5AuthMethodsReceived(typing.NamedTuple):
    """Event emitted when the client sends its acceptable authentication methods.

    The application should inspect ``methods`` and then call
    ``SOCKS5ServerConnection.authenticate`` with the selected method.
    """

    methods: typing.List[SOCKS5AuthMethod]


class SOCKS5UsernamePasswordReceived(typing.NamedTuple):
    """Event emitted when the client sends username/password credentials.

    The application should verify the credentials and then call
    ``SOCKS5ServerConnection.authenticate_username_password`` with the result.
    """

    username: bytes
    password: bytes


class SOCKS5CommandReceived(typing.NamedTuple):
    """Event emitted when an authenticated client sends a CONNECT command.

    The application should perform the connection and then call
    ``SOCKS5ServerConnection.send_command_reply`` with the result.

    Args:
        command: The requested command (always CONNECT, other commands are
            refused automatically).
        atype: The address type of the target.
        addr: The decoded target address (IPv4, IPv6 or domain name).
        port: The target port number.
    """

    command: SOCKS5Command
    atype: SOCKS5AType
    addr: str
    port: int


class SOCKS5DataReceived(typing.NamedTuple):
    """Event emitted with business payload once the tunnel is established."""

    data: bytes


SOCKS5ServerEvent = typing.Union[
    SOCKS5AuthMethodsReceived,
    SOCKS5UsernamePasswordReceived,
    SOCKS5CommandReceived,
    SOCKS5DataReceived,
]


class SOCKS5ServerConnection:
    """Encapsulates the server side of a SOCKS5 connection.

    Receives raw data from the client and produces events. The application
    drives the protocol by deciding the authentication method, verifying
    username/password credentials and reporting the result of CONNECT
    commands. Bytes received while a decision is pending are buffered (up to
    ``max_pending_bytes``) and are never interpreted as authenticated
    commands before the application allows it. A protocol error is terminal:
    the connection transitions to ``CLOSED`` and cannot recover.
    """

    def __init__(self, max_pending_bytes: int = 1024) -> None:
        if max_pending_bytes <= 0:
            raise ValueError("max_pending_bytes must be a positive integer")
        self._data_to_send = bytearray()
        self._received_data = bytearray()
        self._state = SOCKS5ServerState.WAITING_FOR_AUTH_METHODS
        self._max_pending_bytes = max_pending_bytes

    @property
    def state(self) -> SOCKS5ServerState:
        """Returns the current state of the protocol."""
        return self._state

    def receive_data(self, data: bytes) -> typing.List[SOCKS5ServerEvent]:
        """Feeds raw data from the client into the connection.

        Args:
            data: The raw data received from the client.

        Returns:
            A list of events for the application to act upon.

        Raises:
            ProtocolError: If the data does not match the spec or the
                connection is closed. The error is terminal.
        """
        if self._state == SOCKS5ServerState.CLOSED:
            raise ProtocolError("Connection is closed")
        self._received_data += data
        return self._process_events()

    def authenticate(
        self, method: SOCKS5AuthMethod
    ) -> typing.List[SOCKS5ServerEvent]:
        """Selects the authentication method and queues the reply to the client.

        Only meaningful after a ``SOCKS5AuthMethodsReceived`` event. Selecting
        ``NO_ACCEPTABLE_METHODS`` (or any method other than NO_AUTH_REQUIRED
        or USERNAME_PASSWORD) closes the connection after replying.

        Returns:
            Events produced from any input buffered while the decision was
            pending.
        """
        if self._state != SOCKS5ServerState.WAITING_FOR_AUTH_METHOD_DECISION:
            raise ProtocolError("Not waiting for an authentication method decision")
        self._data_to_send += SOCKS5AuthReply(method=method).dumps()
        if method == SOCKS5AuthMethod.USERNAME_PASSWORD:
            self._state = SOCKS5ServerState.WAITING_FOR_USERNAME_PASSWORD
        elif method == SOCKS5AuthMethod.NO_AUTH_REQUIRED:
            self._state = SOCKS5ServerState.WAITING_FOR_COMMAND
        else:
            self._state = SOCKS5ServerState.CLOSED
        return self._process_events()

    def authenticate_username_password(
        self, success: bool
    ) -> typing.List[SOCKS5ServerEvent]:
        """Reports the verification result of username/password credentials.

        Only meaningful after a ``SOCKS5UsernamePasswordReceived`` event. A
        failed verification closes the connection after replying.

        Returns:
            Events produced from any input buffered while the decision was
            pending.
        """
        if self._state != SOCKS5ServerState.WAITING_FOR_USERNAME_PASSWORD_DECISION:
            raise ProtocolError("Not waiting for a username/password decision")
        self._data_to_send += SOCKS5UsernamePasswordReply(success=success).dumps()
        if success:
            self._state = SOCKS5ServerState.WAITING_FOR_COMMAND
        else:
            self._state = SOCKS5ServerState.CLOSED
        return self._process_events()

    def send_command_reply(self, reply: SOCKS5Reply) -> typing.List[SOCKS5ServerEvent]:
        """Reports the result of a CONNECT command to the client.

        Only meaningful after a ``SOCKS5CommandReceived`` event. A successful
        reply establishes the tunnel; any other reply closes the connection.

        Returns:
            Events produced from any input buffered while the decision was
            pending.
        """
        if self._state != SOCKS5ServerState.WAITING_FOR_COMMAND_DECISION:
            raise ProtocolError("Not waiting for a command reply decision")
        self._data_to_send += reply.dumps()
        if reply.reply_code == SOCKS5ReplyCode.SUCCEEDED:
            self._state = SOCKS5ServerState.TUNNEL_READY
        else:
            self._state = SOCKS5ServerState.CLOSED
        return self._process_events()

    def data_to_send(self) -> bytes:
        """Returns the data to be sent via the I/O library of choice.

        Also clears the connection's buffer.
        """
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data

    def _process_events(self) -> typing.List[SOCKS5ServerEvent]:
        events: typing.List[SOCKS5ServerEvent] = []
        try:
            self._process(events)
        except ProtocolError:
            self._state = SOCKS5ServerState.CLOSED
            self._received_data.clear()
            raise
        return events

    def _process(self, events: typing.List[SOCKS5ServerEvent]) -> None:
        while True:
            if self._state == SOCKS5ServerState.TUNNEL_READY:
                if self._received_data:
                    events.append(SOCKS5DataReceived(data=bytes(self._received_data)))
                    self._received_data.clear()
                return

            if len(self._received_data) > self._max_pending_bytes:
                raise ProtocolError("Pending input limit exceeded")

            if self._state == SOCKS5ServerState.WAITING_FOR_AUTH_METHODS:
                event = self._parse_auth_methods_request()
                if event is None:
                    return
                events.append(event)
                self._state = SOCKS5ServerState.WAITING_FOR_AUTH_METHOD_DECISION
            elif self._state == SOCKS5ServerState.WAITING_FOR_USERNAME_PASSWORD:
                event = self._parse_username_password_request()
                if event is None:
                    return
                events.append(event)
                self._state = SOCKS5ServerState.WAITING_FOR_USERNAME_PASSWORD_DECISION
            elif self._state == SOCKS5ServerState.WAITING_FOR_COMMAND:
                event = self._parse_command_request()
                if event is None:
                    return
                if event.command != SOCKS5Command.CONNECT:
                    self._data_to_send += SOCKS5Reply(
                        reply_code=SOCKS5ReplyCode.COMMAND_NOT_SUPPORTED,
                        atype=SOCKS5AType.IPV4_ADDRESS,
                        addr="0.0.0.0",
                        port=0,
                    ).dumps()
                    self._state = SOCKS5ServerState.CLOSED
                    return
                events.append(event)
                self._state = SOCKS5ServerState.WAITING_FOR_COMMAND_DECISION
            else:
                # Waiting for a decision from the application (or closed):
                # any remaining bytes stay buffered and are not interpreted.
                return

    def _parse_auth_methods_request(
        self,
    ) -> typing.Optional[SOCKS5AuthMethodsReceived]:
        if len(self._received_data) < 2:
            return None
        if self._received_data[0] != 0x05:
            raise ProtocolError("Malformed auth methods request")
        nmethods = self._received_data[1]
        if len(self._received_data) < 2 + nmethods:
            return None
        raw_methods = self._received_data[2 : 2 + nmethods]
        del self._received_data[: 2 + nmethods]
        methods = []
        for index in range(nmethods):
            try:
                methods.append(SOCKS5AuthMethod(raw_methods[index : index + 1]))
            except ValueError:
                # Unknown methods are simply not selectable by the application.
                continue
        return SOCKS5AuthMethodsReceived(methods=methods)

    def _parse_username_password_request(
        self,
    ) -> typing.Optional[SOCKS5UsernamePasswordReceived]:
        if len(self._received_data) < 2:
            return None
        if self._received_data[0] != 0x01:
            raise ProtocolError("Malformed username/password request")
        username_length = self._received_data[1]
        if len(self._received_data) < 2 + username_length + 1:
            return None
        password_length = self._received_data[2 + username_length]
        total_length = 2 + username_length + 1 + password_length
        if len(self._received_data) < total_length:
            return None
        username = bytes(self._received_data[2 : 2 + username_length])
        password = bytes(
            self._received_data[2 + username_length + 1 : total_length]
        )
        del self._received_data[:total_length]
        return SOCKS5UsernamePasswordReceived(username=username, password=password)

    def _parse_command_request(self) -> typing.Optional[SOCKS5CommandReceived]:
        if len(self._received_data) < 4:
            return None
        if self._received_data[0] != 0x05:
            raise ProtocolError("Malformed command request")
        try:
            command = SOCKS5Command(self._received_data[1:2])
        except ValueError as exc:
            raise ProtocolError("Unknown command") from exc
        if self._received_data[2] != 0x00:
            raise ProtocolError("Malformed command request: RSV must be 0x00")
        try:
            atype = SOCKS5AType(self._received_data[3:4])
        except ValueError as exc:
            raise ProtocolError("Unknown address type") from exc

        if atype == SOCKS5AType.DOMAIN_NAME:
            if len(self._received_data) < 5:
                return None
            addr_start = 5
            addr_length = self._received_data[4]
        elif atype == SOCKS5AType.IPV4_ADDRESS:
            addr_start = 4
            addr_length = 4
        else:
            addr_start = 4
            addr_length = 16

        total_length = addr_start + addr_length + 2
        if len(self._received_data) < total_length:
            return None
        encoded_addr = bytes(self._received_data[addr_start : addr_start + addr_length])
        port = int.from_bytes(
            self._received_data[addr_start + addr_length : total_length],
            byteorder="big",
        )
        del self._received_data[:total_length]
        try:
            addr = decode_address(AddressType.from_socks5_atype(atype), encoded_addr)
        except (OSError, UnicodeDecodeError) as exc:
            raise ProtocolError("Malformed address in command request") from exc
        return SOCKS5CommandReceived(
            command=command, atype=atype, addr=addr, port=port
        )
