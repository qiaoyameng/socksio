import enum
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

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5AuthMethodsRequest":
        """Unpacks the authentication methods offered by a client."""
        if len(data) < 2 or data[0:1] != b"\x05":
            raise ProtocolError("Malformed authentication methods request")

        method_count = data[1]
        if len(data) != 2 + method_count:
            raise ProtocolError("Malformed authentication methods request")

        methods = []
        for index in range(2, 2 + method_count):
            try:
                method = SOCKS5AuthMethod(data[index : index + 1])
            except ValueError:
                continue
            if method != SOCKS5AuthMethod.NO_ACCEPTABLE_METHODS:
                methods.append(method)

        return cls(methods=methods)


class SOCKS5AuthReply(typing.NamedTuple):
    """Encapsulates a reply from the proxy with the authentication method to be used.

    Args:
        method: The authentication method to be used.

    Raises:
        ProtocolError: If the data does not conform with the expected structure.
    """

    method: SOCKS5AuthMethod

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form."""
        return b"\x05" + self.method

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

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5UsernamePasswordRequest":
        """Unpacks a username/password authentication request from a client."""
        if len(data) < 3 or data[0:1] != b"\x01":
            raise ProtocolError("Malformed username/password authentication request")

        username_length = data[1]
        password_length_index = 2 + username_length
        if len(data) < password_length_index + 1:
            raise ProtocolError("Malformed username/password authentication request")

        password_length = data[password_length_index]
        end = password_length_index + 1 + password_length
        if len(data) != end:
            raise ProtocolError("Malformed username/password authentication request")

        username = data[2:password_length_index]
        password = data[password_length_index + 1 : end]
        return cls(username=username, password=password)


class SOCKS5UsernamePasswordReply(typing.NamedTuple):
    """Encapsulates a username/password authentication reply from the proxy server."""

    success: bool

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form."""
        return b"\x01" + (b"\x00" if self.success else b"\x01")

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

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5CommandRequest":
        """Unpacks a command request from a client."""
        if len(data) < 4 or data[0:1] != b"\x05" or data[2:3] != b"\x00":
            raise ProtocolError("Malformed command request")

        try:
            command = SOCKS5Command(data[1:2])
            atype = SOCKS5AType(data[3:4])
        except ValueError as exc:
            raise ProtocolError("Malformed command request") from exc

        if atype == SOCKS5AType.IPV4_ADDRESS:
            if len(data) != 10:
                raise ProtocolError("Malformed command request")
            addr = data[4:8]
        elif atype == SOCKS5AType.IPV6_ADDRESS:
            if len(data) != 22:
                raise ProtocolError("Malformed command request")
            addr = data[4:20]
        else:
            if len(data) < 5:
                raise ProtocolError("Malformed command request")
            domain_length = data[4]
            if len(data) != 7 + domain_length:
                raise ProtocolError("Malformed command request")
            addr = data[5 : 5 + domain_length]

        return cls(
            command=command,
            atype=atype,
            addr=addr,
            port=int.from_bytes(data[-2:], byteorder="big"),
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
    def from_address(
        cls,
        reply_code: SOCKS5ReplyCode,
        address: typing.Union[StrOrBytes, typing.Tuple[StrOrBytes, int]],
    ) -> "SOCKS5Reply":
        """Builds a reply instance, inferring the address type from ``address``."""
        addr, port = get_address_port_tuple_from_address(address)
        atype, _ = encode_address(addr)
        return cls(
            reply_code=reply_code,
            atype=SOCKS5AType.from_atype(atype),
            addr=addr,
            port=port,
        )

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form."""
        expected_address_type = AddressType.from_socks5_atype(self.atype)
        address_type, encoded_addr = encode_address(self.addr)
        if address_type != expected_address_type:
            raise ProtocolError("Reply address does not match address type")

        packed_addr = encoded_addr
        if address_type == AddressType.DN:
            packed_addr = len(encoded_addr).to_bytes(1, byteorder="big") + packed_addr

        try:
            packed_port = self.port.to_bytes(2, byteorder="big")
        except (AttributeError, OverflowError) as exc:
            raise ProtocolError("Invalid reply port") from exc

        return b"".join(
            [
                b"\x05",
                self.reply_code,
                b"\x00",
                self.atype,
                packed_addr,
                packed_port,
            ]
        )

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
        if len(data) < 4:
            raise ProtocolError("Malformed reply")

        try:
            atype = SOCKS5AType(data[3:4])
            encoded_addr = data[4:-2]
            if atype == SOCKS5AType.IPV4_ADDRESS and len(encoded_addr) != 4:
                raise ProtocolError("Malformed reply")
            if atype == SOCKS5AType.IPV6_ADDRESS and len(encoded_addr) != 16:
                raise ProtocolError("Malformed reply")
            if atype == SOCKS5AType.DOMAIN_NAME and encoded_addr:
                if encoded_addr[0] + 1 == len(encoded_addr):
                    encoded_addr = encoded_addr[1:]

            return cls(
                reply_code=SOCKS5ReplyCode(data[1:2]),
                atype=atype,
                addr=decode_address(
                    AddressType.from_socks5_atype(atype), encoded_addr
                ),
                port=int.from_bytes(data[-2:], byteorder="big"),
            )
        except ValueError as exc:
            raise ProtocolError("Malformed reply") from exc


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


class SOCKS5DataReceived(typing.NamedTuple):
    """Application data received after the SOCKS5 tunnel was established."""

    data: bytes


class SOCKS5State(enum.IntEnum):
    """Enumeration of SOCKS5 protocol states."""

    CLIENT_AUTH_REQUIRED = 1
    SERVER_AUTH_REPLY = 2
    CLIENT_AUTHENTICATED = 3
    TUNNEL_READY = 4
    CLIENT_WAITING_FOR_USERNAME_PASSWORD = 5
    SERVER_VERIFY_USERNAME_PASSWORD = 6
    MUST_CLOSE = 7
    SERVER_WAIT_AUTH_METHODS = 8
    SERVER_WAIT_AUTH_METHOD_DECISION = 9
    SERVER_WAIT_USERNAME_PASSWORD = 10
    SERVER_WAIT_AUTH_DECISION = 11
    SERVER_WAIT_COMMAND = 12
    SERVER_WAIT_COMMAND_DECISION = 13


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


SOCKS5ServerEvent = typing.Union[
    SOCKS5AuthMethodsRequest,
    SOCKS5UsernamePasswordRequest,
    SOCKS5CommandRequest,
    SOCKS5DataReceived,
]
SOCKS5ServerResponse = typing.Union[
    SOCKS5AuthReply, SOCKS5UsernamePasswordReply, SOCKS5Reply
]


class SOCKS5ServerConnection:
    """Sans-I/O server side of a SOCKS5 connection.

    The connection does not own a socket. Received bytes are converted into
    application events, and application decisions are converted into outbound
    protocol bytes.

    Args:
        max_pending_input: Maximum number of bytes retained while waiting for an
            authentication or command decision.
    """

    def __init__(self, max_pending_input: int = 65536) -> None:
        if max_pending_input < 1:
            raise ValueError("max_pending_input must be a positive integer")

        self._max_pending_input = max_pending_input
        self._data_to_send = bytearray()
        self._received_data = bytearray()
        self._offered_auth_methods: typing.List[SOCKS5AuthMethod] = []
        self._pending_command: typing.Optional[SOCKS5CommandRequest] = None
        self._state = SOCKS5State.SERVER_WAIT_AUTH_METHODS

    @property
    def state(self) -> SOCKS5State:
        """Returns the current state of the protocol."""
        return self._state

    def _protocol_error(self, message: str) -> typing.NoReturn:
        self._state = SOCKS5State.MUST_CLOSE
        raise ProtocolError(message)

    @singledispatchmethod
    def send(
        self, response: SOCKS5ServerResponse
    ) -> typing.Optional[SOCKS5ServerEvent]:
        """Applies an application decision and returns any following event."""
        raise NotImplementedError()  # pragma: nocover

    @send.register(SOCKS5AuthReply)
    def _send_auth_reply(
        self, response: SOCKS5AuthReply
    ) -> typing.Optional[SOCKS5ServerEvent]:
        if self._state != SOCKS5State.SERVER_WAIT_AUTH_METHOD_DECISION:
            self._protocol_error(
                "Not currently waiting for an authentication decision"
            )

        method = response.method
        if method in (
            SOCKS5AuthMethod.NO_AUTH_REQUIRED,
            SOCKS5AuthMethod.USERNAME_PASSWORD,
        ):
            if method not in self._offered_auth_methods:
                self._protocol_error("Authentication method was not offered")
        elif method != SOCKS5AuthMethod.NO_ACCEPTABLE_METHODS:
            self._protocol_error("Unsupported authentication method")

        if method in (
            SOCKS5AuthMethod.NO_AUTH_REQUIRED,
            SOCKS5AuthMethod.USERNAME_PASSWORD,
        ):
            self._check_pending_input_limit()

        self._data_to_send += response.dumps()
        if method == SOCKS5AuthMethod.NO_AUTH_REQUIRED:
            self._state = SOCKS5State.SERVER_WAIT_COMMAND
            return self._process()
        if method == SOCKS5AuthMethod.USERNAME_PASSWORD:
            self._state = SOCKS5State.SERVER_WAIT_USERNAME_PASSWORD
            return self._process()

        self._received_data.clear()
        self._state = SOCKS5State.MUST_CLOSE
        return None

    @send.register(SOCKS5UsernamePasswordReply)
    def _send_username_password_reply(
        self, response: SOCKS5UsernamePasswordReply
    ) -> typing.Optional[SOCKS5ServerEvent]:
        if self._state != SOCKS5State.SERVER_WAIT_AUTH_DECISION:
            self._protocol_error(
                "Not currently waiting for an authentication decision"
            )

        if response.success:
            self._check_pending_input_limit()
        self._data_to_send += response.dumps()
        if response.success:
            self._state = SOCKS5State.SERVER_WAIT_COMMAND
            return self._process()

        self._received_data.clear()
        self._state = SOCKS5State.MUST_CLOSE
        return None

    @send.register(SOCKS5Reply)
    def _send_command_reply(
        self, response: SOCKS5Reply
    ) -> typing.Optional[SOCKS5ServerEvent]:
        if self._state != SOCKS5State.SERVER_WAIT_COMMAND_DECISION:
            self._protocol_error("Not currently waiting for a command decision")
        if (
            response.reply_code == SOCKS5ReplyCode.SUCCEEDED
            and self._pending_command is not None
            and self._pending_command.command != SOCKS5Command.CONNECT
        ):
            self._protocol_error("Only CONNECT can establish a tunnel")

        if response.reply_code == SOCKS5ReplyCode.SUCCEEDED:
            self._check_pending_input_limit()
        self._data_to_send += response.dumps()
        if response.reply_code == SOCKS5ReplyCode.SUCCEEDED:
            self._state = SOCKS5State.TUNNEL_READY
            self._pending_command = None
            return self._process()

        self._received_data.clear()
        self._pending_command = None
        self._state = SOCKS5State.MUST_CLOSE
        return None

    def send_data(self, data: bytes) -> None:
        """Queues application payload for an established tunnel."""
        if self._state != SOCKS5State.TUNNEL_READY:
            self._protocol_error("Tunnel is not ready")
        self._data_to_send += data

    def receive_data(self, data: bytes) -> typing.Optional[SOCKS5ServerEvent]:
        """Processes bytes from the client and returns the next protocol event."""
        if self._state == SOCKS5State.MUST_CLOSE:
            self._protocol_error("Connection is closed")

        self._received_data += data
        active_states = (
            SOCKS5State.SERVER_WAIT_AUTH_METHODS,
            SOCKS5State.SERVER_WAIT_USERNAME_PASSWORD,
            SOCKS5State.SERVER_WAIT_COMMAND,
        )
        if self._state == SOCKS5State.TUNNEL_READY and data:
            event_data = bytes(self._received_data)
            self._received_data.clear()
            return SOCKS5DataReceived(data=event_data)

        try:
            event = self._process()
            if self._state in active_states:
                self._check_pending_input_limit()
            return event
        except ProtocolError:
            self._state = SOCKS5State.MUST_CLOSE
            raise

    def data_to_send(self) -> bytes:
        """Returns pending outbound data and clears the send buffer."""
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data

    def _process(self) -> typing.Optional[SOCKS5ServerEvent]:
        if self._state == SOCKS5State.SERVER_WAIT_AUTH_METHODS:
            return self._parse_auth_methods()
        if self._state == SOCKS5State.SERVER_WAIT_USERNAME_PASSWORD:
            return self._parse_username_password()
        if self._state == SOCKS5State.SERVER_WAIT_COMMAND:
            return self._parse_command()
        if self._state == SOCKS5State.TUNNEL_READY and self._received_data:
            event_data = bytes(self._received_data)
            self._received_data.clear()
            return SOCKS5DataReceived(data=event_data)
        return None

    def _check_pending_input_limit(self) -> None:
        if len(self._received_data) > self._max_pending_input:
            self._protocol_error("Pending input limit exceeded")

    def _parse_auth_methods(self) -> typing.Optional[SOCKS5ServerEvent]:
        data = self._received_data
        if len(data) < 2:
            return None

        method_count = data[1]
        message_length = 2 + method_count
        if len(data) < message_length:
            return None

        event = SOCKS5AuthMethodsRequest.loads(bytes(data[:message_length]))
        del data[:message_length]
        self._offered_auth_methods = event.methods
        self._state = SOCKS5State.SERVER_WAIT_AUTH_METHOD_DECISION
        return event

    def _parse_username_password(self) -> typing.Optional[SOCKS5ServerEvent]:
        data = self._received_data
        if not data:
            return None
        if data[0:1] != b"\x01":
            raise ProtocolError("Malformed username/password authentication request")

        message_length = 3 + data[1]
        if len(data) < message_length:
            return None

        password_length_index = 2 + data[1]
        message_length += data[password_length_index]
        if len(data) < message_length:
            return None

        event = SOCKS5UsernamePasswordRequest.loads(bytes(data[:message_length]))
        del data[:message_length]
        self._state = SOCKS5State.SERVER_WAIT_AUTH_DECISION
        return event

    def _parse_command(self) -> typing.Optional[SOCKS5ServerEvent]:
        data = self._received_data
        if len(data) < 4:
            return None
        if data[0:1] != b"\x05" or data[2:3] != b"\x00":
            raise ProtocolError("Malformed command request")

        atype = data[3:4]
        if atype == SOCKS5AType.IPV4_ADDRESS:
            message_length = 10
        elif atype == SOCKS5AType.IPV6_ADDRESS:
            message_length = 22
        elif atype == SOCKS5AType.DOMAIN_NAME:
            if len(data) < 5:
                return None
            message_length = 7 + data[4]
        else:
            raise ProtocolError("Unsupported address type")

        if len(data) < message_length:
            return None

        event = SOCKS5CommandRequest.loads(bytes(data[:message_length]))
        del data[:message_length]
        if event.command != SOCKS5Command.CONNECT:
            reply = SOCKS5Reply(
                reply_code=SOCKS5ReplyCode.COMMAND_NOT_SUPPORTED,
                atype=SOCKS5AType.IPV4_ADDRESS,
                addr="0.0.0.0",
                port=0,
            )
            self._data_to_send += reply.dumps()
            self._state = SOCKS5State.MUST_CLOSE
            return None

        self._pending_command = event
        self._state = SOCKS5State.SERVER_WAIT_COMMAND_DECISION
        return event
