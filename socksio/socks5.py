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


class SOCKS5GSSAPIProtectionLevel(enum.IntEnum):
    """Enumeration of GSSAPI protection levels (RFC 1961)."""

    NONE = 0x00
    INTEGRITY = 0x01
    CONFIDENTIALITY = 0x02


class GSSAPIContext(typing.Protocol):
    """Protocol of the GSSAPI security context injected by the caller.

    The library never acquires credentials by itself: the caller is
    responsible for providing a context object (for example wrapping
    ``gssapi`` or ``pyspnego``) exposing this interface.
    """

    @property
    def complete(self) -> bool:
        """Whether the security context has been fully established."""
        ...  # pragma: nocover

    def step(self, token: bytes) -> bytes:
        """Processes an incoming token and returns the token to send back."""
        ...  # pragma: nocover

    def wrap(self, data: bytes) -> bytes:
        """Signs (and optionally encrypts) data, returning a wrapped token."""
        ...  # pragma: nocover

    def unwrap(self, data: bytes) -> bytes:
        """Verifies a wrapped token and returns the unwrapped data.

        Must raise an exception if the integrity or confidentiality
        protection of the token cannot be verified.
        """
        ...  # pragma: nocover


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


class SOCKS5GSSAPIRequest(typing.NamedTuple):
    """Encapsulates a GSSAPI authentication token message to the proxy (RFC 1961).

    Args:
        token: The token produced by the GSSAPI security context.
    """

    token: bytes

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form.

        Returns:
            The packed request.
        """
        return b"".join(
            [
                b"\x01",  # GSSAPI sub-negotiation version
                b"\x01",  # MTYP: authentication message
                len(self.token).to_bytes(2, byteorder="big"),
                self.token,
            ]
        )


class SOCKS5GSSAPIReply(typing.NamedTuple):
    """Encapsulates a GSSAPI authentication token reply from the proxy.

    Args:
        token: The token to feed into the GSSAPI security context.

    Raises:
        ProtocolError: If the data does not conform with the expected structure.
    """

    token: bytes

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5GSSAPIReply":
        """Unpacks the GSSAPI authentication reply data into an instance.

        Returns:
            The unpacked GSSAPI authentication reply instance.

        Raises:
            ProtocolError: If the data does not match the spec.
        """
        if len(data) < 4:
            raise ProtocolError("Malformed GSSAPI reply")
        if data[0:1] != b"\x01":
            raise ProtocolError("Malformed GSSAPI reply: unsupported version")
        if data[1:2] != b"\x01":
            raise ProtocolError("Malformed GSSAPI reply: unexpected message type")
        token_length = int.from_bytes(data[2:4], byteorder="big")
        if len(data) - 4 != token_length:
            raise ProtocolError("Malformed GSSAPI reply: token length mismatch")
        return cls(token=data[4:])


class SOCKS5GSSAPIProtectionRequest(typing.NamedTuple):
    """Encapsulates a GSSAPI protection level negotiation request (RFC 1961).

    Args:
        protection_levels: Bitmask of the acceptable protection levels.
    """

    protection_levels: int

    def dumps(self) -> bytes:
        """Packs the instance into a raw binary in the appropriate form.

        Returns:
            The packed request.
        """
        return b"".join(
            [
                b"\x01",  # GSSAPI sub-negotiation version
                b"\x02",  # MTYP: protection level negotiation
                b"\x00\x01",  # LEN: a single token byte follows
                self.protection_levels.to_bytes(1, byteorder="big"),
            ]
        )


class SOCKS5GSSAPIProtectionReply(typing.NamedTuple):
    """Encapsulates a GSSAPI protection level negotiation reply from the proxy.

    Args:
        protection_level: The protection level selected by the proxy.

    Raises:
        ProtocolError: If the data does not conform with the expected structure.
    """

    protection_level: SOCKS5GSSAPIProtectionLevel

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS5GSSAPIProtectionReply":
        """Unpacks the GSSAPI protection level reply data into an instance.

        Returns:
            The unpacked GSSAPI protection level reply instance.

        Raises:
            ProtocolError: If the data does not match the spec.
        """
        if len(data) != 5:
            raise ProtocolError("Malformed GSSAPI protection reply")
        if data[0:1] != b"\x01":
            raise ProtocolError(
                "Malformed GSSAPI protection reply: unsupported version"
            )
        if data[1:2] != b"\x02":
            raise ProtocolError(
                "Malformed GSSAPI protection reply: unexpected message type"
            )
        if data[2:4] != b"\x00\x01":
            raise ProtocolError("Malformed GSSAPI protection reply: invalid length")
        try:
            return cls(protection_level=SOCKS5GSSAPIProtectionLevel(data[4]))
        except ValueError as exc:
            raise ProtocolError(
                "Malformed GSSAPI protection reply: unknown protection level"
            ) from exc


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
    SERVER_GSSAPI_TOKEN_REPLY = 8
    SERVER_GSSAPI_PROTECTION_REPLY = 9


SOCKS5RequestType = typing.Union[SOCKS5AuthMethodsRequest, SOCKS5CommandRequest]


class SOCKS5Connection:
    """Encapsulates a SOCKS5 connection.

    Packs request objects into data suitable to be send and unpacks reply
    data into their appropriate reply objects.

    If the proxy selects the GSSAPI authentication method, the connection
    drives the RFC 1961 sub-negotiation using the injected ``gssapi_context``:
    authentication tokens are exchanged until the context is complete, then
    a protection level is negotiated. If integrity or confidentiality
    protection is selected, the SOCKS command request/reply and all
    subsequent application data are wrapped with the context and framed as
    ``2-byte length + wrapped token`` records on the wire.

    Args:
        gssapi_context: A caller-provided GSSAPI security context exposing
            ``step``, ``wrap``, ``unwrap`` and a ``complete`` property.
            The library never looks up credentials by itself.
        minimum_gssapi_protection_level: The minimum protection level the
            proxy is allowed to select. Negotiations below this level are
            rejected and the connection must be closed.
    """

    def __init__(
        self,
        gssapi_context: typing.Optional[GSSAPIContext] = None,
        minimum_gssapi_protection_level: SOCKS5GSSAPIProtectionLevel = (
            SOCKS5GSSAPIProtectionLevel.NONE
        ),
    ) -> None:
        self._data_to_send = bytearray()
        self._received_data = bytearray()
        self._state = SOCKS5State.CLIENT_AUTH_REQUIRED
        self._gssapi_context = gssapi_context
        self._minimum_gssapi_protection_level = minimum_gssapi_protection_level
        self._gssapi_protection_level: typing.Optional[
            SOCKS5GSSAPIProtectionLevel
        ] = None

    @property
    def state(self) -> SOCKS5State:
        """Returns the current state of the protocol."""
        return self._state

    @property
    def _gssapi_protected(self) -> bool:
        return (
            self._gssapi_protection_level is not None
            and self._gssapi_protection_level != SOCKS5GSSAPIProtectionLevel.NONE
        )

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
        self._data_to_send += self._protect(request.dumps())

    def send_data(self, data: bytes) -> None:
        """Packs application data to be sent through the established tunnel.

        If GSSAPI integrity or confidentiality protection was negotiated,
        the data is wrapped with the GSSAPI context and framed as a record.

        Args:
            data: The application data to send.
        """
        if self._state != SOCKS5State.TUNNEL_READY:
            raise ProtocolError("The SOCKS5 tunnel is not ready yet")
        self._data_to_send += self._protect(data)

    def receive_data(
        self, data: bytes
    ) -> typing.Union[
        SOCKS5AuthReply,
        SOCKS5Reply,
        SOCKS5UsernamePasswordReply,
        SOCKS5GSSAPIReply,
        SOCKS5GSSAPIProtectionReply,
        bytes,
        None,
    ]:
        """Unpacks response data into a reply object.

        Args:
            data: The raw response data from the proxy server.

        Returns:
            A reply instance corresponding to the connection state and reply data.
            Once the tunnel is ready, returns the (unwrapped) application data,
            or None if a complete protected record has not been received yet.
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
                        "GSSAPI authentication requires a GSSAPI context"
                    )
                self._step_gssapi(b"")
            return auth_reply

        if self._state == SOCKS5State.SERVER_VERIFY_USERNAME_PASSWORD:
            username_password_reply = SOCKS5UsernamePasswordReply.loads(data)
            if username_password_reply.success:
                self._state = SOCKS5State.CLIENT_AUTHENTICATED
            else:
                self._state = SOCKS5State.MUST_CLOSE
            return username_password_reply

        if self._state == SOCKS5State.SERVER_GSSAPI_TOKEN_REPLY:
            try:
                gssapi_reply = SOCKS5GSSAPIReply.loads(data)
            except ProtocolError:
                self._state = SOCKS5State.MUST_CLOSE
                raise
            self._step_gssapi(gssapi_reply.token)
            return gssapi_reply

        if self._state == SOCKS5State.SERVER_GSSAPI_PROTECTION_REPLY:
            try:
                protection_reply = SOCKS5GSSAPIProtectionReply.loads(data)
            except ProtocolError:
                self._state = SOCKS5State.MUST_CLOSE
                raise
            if (
                protection_reply.protection_level
                < self._minimum_gssapi_protection_level
            ):
                self._state = SOCKS5State.MUST_CLOSE
                raise ProtocolError(
                    "The proxy selected a GSSAPI protection level "
                    "below the required minimum"
                )
            self._gssapi_protection_level = protection_reply.protection_level
            self._state = SOCKS5State.CLIENT_AUTHENTICATED
            return protection_reply

        if self._state == SOCKS5State.CLIENT_AUTHENTICATED:
            if self._gssapi_protected:
                unwrapped_data = self._receive_protected_record(data)
                if unwrapped_data is None:
                    return None
                data = unwrapped_data
            reply = SOCKS5Reply.loads(data)
            if reply.reply_code == SOCKS5ReplyCode.SUCCEEDED:
                self._state = SOCKS5State.TUNNEL_READY
            else:
                self._state = SOCKS5State.MUST_CLOSE

            return reply

        if self._state == SOCKS5State.TUNNEL_READY:
            if self._gssapi_protected:
                return self._receive_protected_record(data)
            return data

        if self._state == SOCKS5State.MUST_CLOSE:
            raise ProtocolError("The connection is failed and must be closed")

        raise NotImplementedError()  # pragma: nocover

    def _step_gssapi(self, token: bytes) -> None:
        """Advances the GSSAPI context and queues the next protocol message."""
        assert self._gssapi_context is not None
        try:
            output_token = self._gssapi_context.step(token)
        except Exception as exc:
            self._state = SOCKS5State.MUST_CLOSE
            raise ProtocolError("GSSAPI authentication failed") from exc
        if not self._gssapi_context.complete:
            self._data_to_send += SOCKS5GSSAPIRequest(token=output_token).dumps()
            self._state = SOCKS5State.SERVER_GSSAPI_TOKEN_REPLY
            return
        if output_token:
            self._data_to_send += SOCKS5GSSAPIRequest(token=output_token).dumps()
        self._data_to_send += SOCKS5GSSAPIProtectionRequest(
            protection_levels=self._acceptable_gssapi_protection_levels()
        ).dumps()
        self._state = SOCKS5State.SERVER_GSSAPI_PROTECTION_REPLY

    def _acceptable_gssapi_protection_levels(self) -> int:
        """Returns the bitmask of protection levels acceptable to offer."""
        levels = 0
        minimum = self._minimum_gssapi_protection_level
        if minimum <= SOCKS5GSSAPIProtectionLevel.INTEGRITY:
            levels |= SOCKS5GSSAPIProtectionLevel.INTEGRITY
        if minimum <= SOCKS5GSSAPIProtectionLevel.CONFIDENTIALITY:
            levels |= SOCKS5GSSAPIProtectionLevel.CONFIDENTIALITY
        return levels

    def _protect(self, data: bytes) -> bytes:
        """Wraps and frames data if GSSAPI protection was negotiated."""
        if not self._gssapi_protected:
            return data
        assert self._gssapi_context is not None
        try:
            token = self._gssapi_context.wrap(data)
        except Exception as exc:
            self._state = SOCKS5State.MUST_CLOSE
            raise ProtocolError("Failed to protect data with GSSAPI") from exc
        return len(token).to_bytes(2, byteorder="big") + token

    def _receive_protected_record(self, data: bytes) -> typing.Optional[bytes]:
        """Buffers a protected record and returns its verified plaintext.

        Returns None if a complete record has not been received yet. Data
        that fails verification is never returned: the connection must be
        closed instead of falling back to plaintext.
        """
        self._received_data += data
        if len(self._received_data) < 2:
            return None
        token_length = int.from_bytes(self._received_data[0:2], byteorder="big")
        if len(self._received_data) < 2 + token_length:
            return None
        token = bytes(self._received_data[2 : 2 + token_length])
        del self._received_data[: 2 + token_length]
        assert self._gssapi_context is not None
        try:
            return self._gssapi_context.unwrap(token)
        except Exception as exc:
            self._state = SOCKS5State.MUST_CLOSE
            raise ProtocolError("Failed to verify protected data with GSSAPI") from exc

    def data_to_send(self) -> bytes:
        """Returns the data to be sent via the I/O library of choice.

        Also clears the connection's buffer.
        """
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data
