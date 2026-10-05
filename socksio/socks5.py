import enum
import typing
from functools import singledispatchmethod

from ._types import StrOrBytes
from .exceptions import ProtocolError
from .gssapi import (
    GSSAPIContext,
    GSSAPIMessageType,
    GSSAPIProtectionLevel,
    GSSAPIState,
    SOCKS5GSSAPIAuthenticator,
    decode_message,
    encode_message,
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
    CLIENT_GSSAPI_AUTHENTICATION = 8


SOCKS5RequestType = typing.Union[SOCKS5AuthMethodsRequest, SOCKS5CommandRequest]


class SOCKS5Connection:
    """Encapsulates a SOCKS5 connection.

    Packs request objects into data suitable to be send and unpacks reply
    data into their appropriate reply objects.

    Args:
        gssapi_context: An optional injected GSSAPI security context used
            when the proxy selects the GSSAPI authentication method.
        min_gssapi_protection: The minimum GSSAPI protection level acceptable
            for the connection.
    """

    def __init__(
        self,
        gssapi_context: typing.Optional[GSSAPIContext] = None,
        min_gssapi_protection: GSSAPIProtectionLevel = GSSAPIProtectionLevel.INTEGRITY,
    ) -> None:
        self._data_to_send = bytearray()
        self._received_data = bytearray()
        self._state = SOCKS5State.CLIENT_AUTH_REQUIRED
        self._gssapi_context = gssapi_context
        self._min_gssapi_protection = min_gssapi_protection
        self._gssapi_authenticator: typing.Optional[SOCKS5GSSAPIAuthenticator] = None
        self._gssapi_protection: typing.Optional[GSSAPIProtectionLevel] = None

    @property
    def state(self) -> SOCKS5State:
        """Returns the current state of the protocol."""
        return self._state

    @property
    def gssapi_protection(self) -> typing.Optional[GSSAPIProtectionLevel]:
        """Returns the negotiated GSSAPI protection level, if any."""
        return self._gssapi_protection

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
        if self._state not in (
            SOCKS5State.CLIENT_AUTHENTICATED,
            SOCKS5State.TUNNEL_READY,
        ):
            raise ProtocolError(
                "SOCKS5 connections must be authenticated before sending a request"
            )
        self._data_to_send += self._wrap_outgoing(request.dumps())

    def send_data(self, data: bytes) -> None:
        """Packs application data to be sent through the established tunnel.

        If a GSSAPI protection level was negotiated the data is wrapped and
        framed as an RFC 1961 subsequent message.
        """
        if self._state != SOCKS5State.TUNNEL_READY:
            raise ProtocolError("SOCKS5 tunnel is not ready")
        self._data_to_send += self._wrap_outgoing(data)

    def receive_data(
        self, data: bytes
    ) -> typing.Optional[
        typing.Union[SOCKS5AuthReply, SOCKS5Reply, SOCKS5UsernamePasswordReply, bytes]
    ]:
        """Unpacks response data into a reply object.

        Args:
            data: The raw response data from the proxy server.

        Returns:
            A reply instance corresponding to the connection state and reply data.
            During GSSAPI negotiation, or while a wrapped record is still
            incomplete, None is returned. In the data phase of a
            GSSAPI-protected tunnel, unwrapped application data is returned.
        """
        if self._state == SOCKS5State.SERVER_AUTH_REPLY:
            auth_reply = SOCKS5AuthReply.loads(data)
            if auth_reply.method == SOCKS5AuthMethod.USERNAME_PASSWORD:
                self._state = SOCKS5State.CLIENT_WAITING_FOR_USERNAME_PASSWORD
            elif auth_reply.method == SOCKS5AuthMethod.NO_AUTH_REQUIRED:
                self._state = SOCKS5State.CLIENT_AUTHENTICATED
            elif auth_reply.method == SOCKS5AuthMethod.GSSAPI:
                if self._gssapi_context is None:
                    self._state = SOCKS5State.MUST_CLOSE
                    raise ProtocolError(
                        "The proxy selected GSSAPI authentication but no "
                        "GSSAPI context was provided"
                    )
                self._gssapi_authenticator = SOCKS5GSSAPIAuthenticator(
                    self._gssapi_context, self._min_gssapi_protection
                )
                self._data_to_send += self._gssapi_authenticator.data_to_send()
                self._state = SOCKS5State.CLIENT_GSSAPI_AUTHENTICATION
            return auth_reply

        if self._state == SOCKS5State.CLIENT_GSSAPI_AUTHENTICATION:
            assert self._gssapi_authenticator is not None
            try:
                self._gssapi_authenticator.receive_data(data)
            except ProtocolError:
                self._state = SOCKS5State.MUST_CLOSE
                raise
            self._data_to_send += self._gssapi_authenticator.data_to_send()
            if self._gssapi_authenticator.state == GSSAPIState.AUTHENTICATED:
                self._gssapi_protection = self._gssapi_authenticator.protection_level
                self._state = SOCKS5State.CLIENT_AUTHENTICATED
            return None

        if self._state == SOCKS5State.SERVER_VERIFY_USERNAME_PASSWORD:
            username_password_reply = SOCKS5UsernamePasswordReply.loads(data)
            if username_password_reply.success:
                self._state = SOCKS5State.CLIENT_AUTHENTICATED
            else:
                self._state = SOCKS5State.MUST_CLOSE
            return username_password_reply

        if self._state == SOCKS5State.CLIENT_AUTHENTICATED:
            if self._gssapi_protection is not None:
                records = self._unwrap_records(data)
                if not records:
                    return None
                if len(records) != 1:
                    self._state = SOCKS5State.MUST_CLOSE
                    raise ProtocolError("Expected a single GSSAPI record for the reply")
                data = records[0]
            reply = SOCKS5Reply.loads(data)
            if reply.reply_code == SOCKS5ReplyCode.SUCCEEDED:
                self._state = SOCKS5State.TUNNEL_READY
            else:
                self._state = SOCKS5State.MUST_CLOSE

            return reply

        if (
            self._state == SOCKS5State.TUNNEL_READY
            and self._gssapi_protection is not None
        ):
            records = self._unwrap_records(data)
            if not records:
                return None
            return b"".join(records)

        raise NotImplementedError()  # pragma: nocover

    def _wrap_outgoing(self, data: bytes) -> bytes:
        if self._gssapi_protection is None:
            return data
        assert self._gssapi_context is not None
        try:
            token = self._gssapi_context.wrap(data)
        except Exception as exc:
            self._state = SOCKS5State.MUST_CLOSE
            raise ProtocolError("The GSSAPI context failed to wrap data") from exc
        return encode_message(GSSAPIMessageType.SUBSEQUENT_MESSAGE, token)

    def _unwrap_records(self, data: bytes) -> typing.List[bytes]:
        """Buffers data and unwraps every complete subsequent message record.

        Records are only returned after the GSSAPI context has verified them.
        """
        assert self._gssapi_context is not None
        self._received_data += data
        records = []
        try:
            while True:
                decoded = decode_message(self._received_data)
                if decoded is None:
                    break
                message_type, token = decoded
                if message_type != GSSAPIMessageType.SUBSEQUENT_MESSAGE:
                    raise ProtocolError("Expected a GSSAPI subsequent message record")
                try:
                    records.append(self._gssapi_context.unwrap(token))
                except Exception as exc:
                    raise ProtocolError("A GSSAPI record failed verification") from exc
        except ProtocolError:
            self._state = SOCKS5State.MUST_CLOSE
            raise
        return records

    def data_to_send(self) -> bytes:
        """Returns the data to be sent via the I/O library of choice.

        Also clears the connection's buffer.
        """
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data
