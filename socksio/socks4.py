import enum
import typing

from ._types import StrOrBytes
from .exceptions import ProtocolError, SOCKSError
from .utils import (
    AddressType,
    decode_address,
    encode_address,
    get_address_port_tuple_from_address,
)


class SOCKS4ReplyCode(bytes, enum.Enum):
    """Enumeration of SOCKS4 reply codes."""

    REQUEST_GRANTED = b"\x5a"
    REQUEST_REJECTED_OR_FAILED = b"\x5b"
    CONNECTION_FAILED = b"\x5c"
    AUTHENTICATION_FAILED = b"\x5d"


class SOCKS4Command(bytes, enum.Enum):
    """Enumeration of SOCKS4 command codes."""

    CONNECT = b"\x01"
    BIND = b"\x02"


class SOCKS4Request(typing.NamedTuple):
    """Encapsulates a request to the SOCKS4 proxy server

    Args:
        command: The command to request.
        port: The port number to connect to on the target host.
        addr: IP address of the target host.
        user_id: Optional user ID to be included in the request, if not supplied
            the user *must* provide one in the packing operation.
    """

    command: SOCKS4Command
    port: int
    addr: bytes
    user_id: typing.Optional[bytes] = None

    @classmethod
    def from_address(
        cls,
        command: SOCKS4Command,
        address: typing.Union[StrOrBytes, typing.Tuple[StrOrBytes, int]],
        user_id: typing.Optional[bytes] = None,
    ) -> "SOCKS4Request":
        """Convenience class method to build an instance from command and address.

        Args:
            command: The command to request.
            address: A string in the form 'HOST:PORT' or a tuple of ip address string
                and port number.
            user_id: Optional user ID.

        Returns:
            A SOCKS4Request instance.

        Raises:
            SOCKSError: If a domain name or IPv6 address was supplied.
        """
        address, port = get_address_port_tuple_from_address(address)
        atype, encoded_addr = encode_address(address)
        if atype != AddressType.IPV4:
            raise SOCKSError(
                "IPv6 addresses and domain names are not supported by SOCKS4"
            )
        return cls(command=command, addr=encoded_addr, port=port, user_id=user_id)

    def dumps(self, user_id: typing.Optional[bytes] = None) -> bytes:
        """Packs the instance into a raw binary in the appropriate form.

        Args:
            user_id: Optional user ID as an override, if not provided the instance's
                will be used, if none was provided at initialization an error is raised.

        Returns:
            The packed request.

        Raises:
            SOCKSError: If no user was specified in this call or on initialization.
        """
        user_id = user_id or self.user_id
        if user_id is None:
            raise SOCKSError("SOCKS4 requires a user_id, none was specified")

        return b"".join(
            [
                b"\x04",
                self.command,
                (self.port).to_bytes(2, byteorder="big"),
                self.addr,
                user_id,
                b"\x00",
            ]
        )


class SOCKS4ARequest(typing.NamedTuple):
    """Encapsulates a request to the SOCKS4A proxy server

    Args:
        command: The command to request.
        port: The port number to connect to on the target host.
        addr: IP address of the target host.
        user_id: Optional user ID to be included in the request, if not supplied
            the user *must* provide one in the packing operation.
    """

    command: SOCKS4Command
    port: int
    addr: bytes
    user_id: typing.Optional[bytes] = None

    @classmethod
    def from_address(
        cls,
        command: SOCKS4Command,
        address: typing.Union[StrOrBytes, typing.Tuple[StrOrBytes, int]],
        user_id: typing.Optional[bytes] = None,
    ) -> "SOCKS4ARequest":
        """Convenience class method to build an instance from command and address.

        Args:
            command: The command to request.
            address: A string in the form 'HOST:PORT' or a tuple of ip address string
                and port number.
            user_id: Optional user ID.

        Returns:
            A SOCKS4ARequest instance.
        """
        address, port = get_address_port_tuple_from_address(address)
        atype, encoded_addr = encode_address(address)
        return cls(command=command, addr=encoded_addr, port=port, user_id=user_id)

    def dumps(self, user_id: typing.Optional[bytes] = None) -> bytes:
        """Packs the instance into a raw binary in the appropriate form.

        Args:
            user_id: Optional user ID as an override, if not provided the instance's
                will be used, if none was provided at initialization an error is raised.

        Returns:
            The packed request.

        Raises:
            SOCKSError: If no user was specified in this call or on initialization.
        """
        user_id = user_id or self.user_id
        if user_id is None:
            raise SOCKSError("SOCKS4 requires a user_id, none was specified")

        return b"".join(
            [
                b"\x04",
                self.command,
                (self.port).to_bytes(2, byteorder="big"),
                b"\x00\x00\x00\xff",  # arbitrary final non-zero byte
                user_id,
                b"\x00",
                self.addr,
                b"\x00",
            ]
        )


class SOCKS4Reply(typing.NamedTuple):
    """Encapsulates a reply from the SOCKS4 proxy server

    Args:
        reply_code: The code representing the type of reply.
        port: The port number returned.
        addr: Optional IP address returned.
    """

    reply_code: SOCKS4ReplyCode
    port: int
    addr: typing.Optional[str]

    @classmethod
    def loads(cls, data: bytes) -> "SOCKS4Reply":
        """Unpacks the reply data into an instance.

        Returns:
            The unpacked reply instance.

        Raises:
            ProtocolError: If the data does not match the spec.
        """
        if len(data) != 8 or data[0:1] != b"\x00":
            raise ProtocolError("Malformed reply")

        try:
            return cls(
                reply_code=SOCKS4ReplyCode(data[1:2]),
                port=int.from_bytes(data[2:4], byteorder="big"),
                addr=decode_address(AddressType.IPV4, data[4:8]),
            )
        except ValueError as exc:
            raise ProtocolError("Malformed reply") from exc


class SOCKS4State(enum.IntEnum):
    """Enumeration of SOCKS4 protocol states."""

    CLIENT_REQUEST_REQUIRED = 1
    SERVER_REPLY = 2
    SERVER_BIND_FIRST_REPLY = 3
    SERVER_BIND_SECOND_REPLY = 4
    TUNNEL_READY = 5
    MUST_CLOSE = 6


class SOCKS4Connection:
    """Encapsulates a SOCKS4 and SOCKS4A connection.

    Packs request objects into data suitable to be send and unpacks reply
    data into their appropriate reply objects.

    BIND requests receive two replies: the first reports the address the
    proxy is listening on and the second reports the connecting host. Only
    after a successful second reply is the tunnel ready.

    Args:
        user_id: The user ID to be sent as part of the requests.
    """

    def __init__(self, user_id: bytes):
        self.user_id = user_id

        self._data_to_send = bytearray()
        self._received_data = bytearray()
        self._tunnel_data = bytearray()
        self._state = SOCKS4State.CLIENT_REQUEST_REQUIRED

    @property
    def state(self) -> SOCKS4State:
        """Returns the current state of the protocol."""
        return self._state

    def send(self, request: typing.Union[SOCKS4Request, SOCKS4ARequest]) -> None:
        """Packs a request object and adds it to the send data buffer.

        Also progresses the protocol state of the connection.

        Args:
            request: The request instance to be packed.

        Raises:
            ProtocolError: If called while waiting for a BIND reply.
        """
        if self._state in (
            SOCKS4State.SERVER_BIND_FIRST_REPLY,
            SOCKS4State.SERVER_BIND_SECOND_REPLY,
        ):
            raise ProtocolError(
                "Cannot send another command while waiting for a BIND reply"
            )
        user_id = request.user_id or self.user_id
        self._data_to_send += request.dumps(user_id=user_id)
        if request.command == SOCKS4Command.BIND:
            self._state = SOCKS4State.SERVER_BIND_FIRST_REPLY
        else:
            self._state = SOCKS4State.SERVER_REPLY

    def receive_data(
        self, data: bytes
    ) -> typing.Optional[typing.Union[SOCKS4Reply, bytes]]:
        """Unpacks response data into a reply object.

        Args:
            data: The raw response data from the proxy server.

        Returns:
            The appropriate reply object, ``None`` if a BIND reply was only
            partially received, or raw ``bytes`` once the tunnel is ready.
        """
        if self._state == SOCKS4State.TUNNEL_READY:
            self._tunnel_data += data
            return self.tunnel_data()

        if self._state in (
            SOCKS4State.SERVER_BIND_FIRST_REPLY,
            SOCKS4State.SERVER_BIND_SECOND_REPLY,
        ):
            return self._receive_bind_reply(data)

        self._received_data += data
        reply = SOCKS4Reply.loads(bytes(self._received_data))
        if reply.reply_code == SOCKS4ReplyCode.REQUEST_GRANTED:
            self._state = SOCKS4State.TUNNEL_READY
        else:
            self._state = SOCKS4State.MUST_CLOSE
        return reply

    def _receive_bind_reply(self, data: bytes) -> typing.Optional[SOCKS4Reply]:
        """Parses one of the two replies expected from a BIND request.

        Replies may arrive split across arbitrarily many ``receive_data``
        calls, in which case ``None`` is returned until the full 8 byte
        reply is available. Trailing bytes after a complete final reply are
        preserved as the first bytes of tunnel data.
        """
        self._received_data += data
        if len(self._received_data) < 8:
            return None

        frame = bytes(self._received_data[:8])
        extra = bytes(self._received_data[8:])
        self._received_data = bytearray()
        try:
            reply = SOCKS4Reply.loads(frame)
        except ProtocolError:
            self._state = SOCKS4State.MUST_CLOSE
            raise

        if reply.reply_code != SOCKS4ReplyCode.REQUEST_GRANTED:
            self._state = SOCKS4State.MUST_CLOSE
            return reply

        if self._state == SOCKS4State.SERVER_BIND_FIRST_REPLY:
            self._state = SOCKS4State.SERVER_BIND_SECOND_REPLY
            if extra:
                self._received_data += extra
            return reply

        self._state = SOCKS4State.TUNNEL_READY
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
