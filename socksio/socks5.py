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

    @staticmethod
    def frame_length(data: bytes) -> typing.Optional[int]:
        """Returns the length of the first complete reply frame in ``data``.

        Returns ``None`` if ``data`` does not yet contain a full reply.

        Raises:
            ProtocolError: If enough data was received to tell the reply
                does not conform to the spec.
        """
        if not data:
            return None
        if data[0:1] != b"\x05":
            raise ProtocolError("Malformed reply")
        if len(data) < 4:
            return None

        try:
            atype = SOCKS5AType(data[3:4])
        except ValueError as exc:
            raise ProtocolError("Malformed reply") from exc

        if atype == SOCKS5AType.IPV4_ADDRESS:
            address_length = 4
        elif atype == SOCKS5AType.IPV6_ADDRESS:
            address_length = 16
        else:
            if len(data) < 5:
                return None
            address_length = data[4] + 1

        frame_length = 4 + address_length + 2
        if len(data) < frame_length:
            return None
        return frame_length


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
    SERVER_BIND_FIRST_REPLY = 8
    SERVER_BIND_SECOND_REPLY = 9


SOCKS5RequestType = typing.Union[SOCKS5AuthMethodsRequest, SOCKS5CommandRequest]


class SOCKS5Connection:
    """Encapsulates a SOCKS5 connection.

    Packs request objects into data suitable to be send and unpacks reply
    data into their appropriate reply objects.
    """

    def __init__(self) -> None:
        self._data_to_send = bytearray()
        self._received_data = bytearray()
        self._tunnel_data = bytearray()
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
        if self._state in (
            SOCKS5State.SERVER_BIND_FIRST_REPLY,
            SOCKS5State.SERVER_BIND_SECOND_REPLY,
        ):
            raise ProtocolError(
                "Cannot send another command while waiting for a BIND reply"
            )
        self._data_to_send += request.dumps()
        if request.command == SOCKS5Command.BIND:
            self._state = SOCKS5State.SERVER_BIND_FIRST_REPLY

    def receive_data(
        self, data: bytes
    ) -> typing.Optional[
        typing.Union[SOCKS5AuthReply, SOCKS5Reply, SOCKS5UsernamePasswordReply, bytes]
    ]:
        """Unpacks response data into a reply object.

        For BIND requests two replies are expected: the first reply confirms
        that the server is listening and the second reply confirms that the
        remote host has connected. Only after the second successful reply is
        the tunnel ready.

        Args:
            data: The raw response data from the proxy server.

        Returns:
            A reply instance corresponding to the connection state and reply
            data. ``None`` is returned when not enough data was received to
            parse a complete reply. Once the tunnel is ready the raw tunnel
            data is returned as ``bytes``.
        """
        if self._state == SOCKS5State.TUNNEL_READY:
            self._tunnel_data += data
            return self.tunnel_data()

        if self._state in (
            SOCKS5State.SERVER_BIND_FIRST_REPLY,
            SOCKS5State.SERVER_BIND_SECOND_REPLY,
        ):
            return self._receive_bind_reply(data)

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

    def _receive_bind_reply(self, data: bytes) -> typing.Optional[SOCKS5Reply]:
        """Parses one of the two replies expected from a BIND request.

        Replies may arrive split across arbitrarily many ``receive_data``
        calls, in which case ``None`` is returned until a full reply is
        available. Trailing bytes after a complete final reply are preserved
        as the first bytes of tunnel data.
        """
        self._received_data += data
        try:
            frame_length = SOCKS5Reply.frame_length(bytes(self._received_data))
            if frame_length is None:
                return None

            frame = bytes(self._received_data[:frame_length])
            extra = bytes(self._received_data[frame_length:])
            self._received_data = bytearray()
            if frame[3:4] == SOCKS5AType.DOMAIN_NAME:
                # The RFC frame includes a 1 byte domain length prefix which
                # SOCKS5Reply.loads does not expect, strip it.
                frame = frame[:4] + frame[5:]
            reply = SOCKS5Reply.loads(frame)
        except ProtocolError:
            self._received_data = bytearray()
            self._state = SOCKS5State.MUST_CLOSE
            raise

        if reply.reply_code != SOCKS5ReplyCode.SUCCEEDED:
            self._state = SOCKS5State.MUST_CLOSE
            return reply

        if self._state == SOCKS5State.SERVER_BIND_FIRST_REPLY:
            self._state = SOCKS5State.SERVER_BIND_SECOND_REPLY
            if extra:
                self._received_data += extra
            return reply

        self._state = SOCKS5State.TUNNEL_READY
        if extra:
            self._tunnel_data += extra
        return reply

    def tunnel_data(self) -> bytes:
        """Returns the raw tunnel data received, clearing the buffer.

        The first tunnel data may already have been received together with
        the final BIND reply.
        """
        data = bytes(self._tunnel_data)
        self._tunnel_data = bytearray()
        return data

    def data_to_send(self) -> bytes:
        """Returns the data to be sent via the I/O library of choice.

        Also clears the connection's buffer.
        """
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data
