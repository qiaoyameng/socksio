"""Sans-I/O implementation of the SOCKS5 GSSAPI authentication method (RFC 1961).

The GSSAPI security context is injected by the caller: the library neither
imports Kerberos libraries nor looks up machine credentials on its own.
"""

import enum
import typing

from .exceptions import ProtocolError

GSSAPI_VERSION = 0x01


class GSSAPIMessageType(enum.IntEnum):
    """Enumeration of the GSSAPI message types (MTYP) defined by RFC 1961."""

    AUTHENTICATION = 0x01
    PROTECTION_NEGOTIATION = 0x02
    SUBSEQUENT_MESSAGE = 0x03
    ABORT = 0xFF


class GSSAPIProtectionLevel(enum.IntEnum):
    """Enumeration of the protection levels negotiable via RFC 1961."""

    NONE = 0x00
    INTEGRITY = 0x01
    CONFIDENTIALITY = 0x02
    SELECTIVE = 0x03


class GSSAPIState(enum.IntEnum):
    """Enumeration of the GSSAPI sub-negotiation states."""

    TOKEN_EXCHANGE = 1
    PROTECTION_NEGOTIATION = 2
    AUTHENTICATED = 3
    MUST_CLOSE = 4


class GSSAPIContext(typing.Protocol):
    """Interface expected from an injected GSSAPI security context."""

    @property
    def complete(self) -> bool:
        """Whether the security context has been fully established."""
        ...  # pragma: nocover

    def step(self, token: bytes) -> bytes:
        """Processes an incoming token and returns the next token to send."""
        ...  # pragma: nocover

    def wrap(self, data: bytes) -> bytes:
        """Signs (and optionally seals) data, returning the wrapped token."""
        ...  # pragma: nocover

    def unwrap(self, data: bytes) -> bytes:
        """Verifies a wrapped token and returns the data it protects."""
        ...  # pragma: nocover


def encode_message(message_type: GSSAPIMessageType, token: bytes) -> bytes:
    """Packs a token into a VER | MTYP | LEN | TOKEN message."""
    return b"".join(
        [
            bytes([GSSAPI_VERSION]),
            bytes([message_type]),
            len(token).to_bytes(2, byteorder="big"),
            token,
        ]
    )


def decode_message(
    buffer: bytearray,
) -> typing.Optional[typing.Tuple[GSSAPIMessageType, bytes]]:
    """Pops a complete message from the buffer, or returns None if incomplete.

    Raises:
        ProtocolError: If the version or message type is invalid.
    """
    if not buffer:
        return None
    if buffer[0] != GSSAPI_VERSION:
        raise ProtocolError("Invalid GSSAPI message version")
    if len(buffer) < 4:
        return None
    length = int.from_bytes(buffer[2:4], byteorder="big")
    if len(buffer) < 4 + length:
        return None
    try:
        message_type = GSSAPIMessageType(buffer[1])
    except ValueError as exc:
        raise ProtocolError("Invalid GSSAPI message type") from exc
    token = bytes(buffer[4 : 4 + length])
    del buffer[: 4 + length]
    return message_type, token


class SOCKS5GSSAPIAuthenticator:
    """Sans-I/O driver for the RFC 1961 authentication token exchange and
    protection level negotiation phases.

    Args:
        context: The injected GSSAPI security context.
        min_protection: The minimum protection level acceptable for the
            connection. Negotiations below this level are rejected and the
            connection must be closed; it never falls back to plaintext.
    """

    def __init__(
        self,
        context: GSSAPIContext,
        min_protection: GSSAPIProtectionLevel = GSSAPIProtectionLevel.INTEGRITY,
    ) -> None:
        if min_protection < GSSAPIProtectionLevel.INTEGRITY:
            raise ValueError("The minimum protection level must require integrity")
        self._context = context
        self._min_protection = min_protection
        self._state = GSSAPIState.TOKEN_EXCHANGE
        self._buffer = bytearray()
        self._data_to_send = bytearray()
        self.protection_level: typing.Optional[GSSAPIProtectionLevel] = None
        self._step(b"")

    @property
    def state(self) -> GSSAPIState:
        """Returns the current state of the sub-negotiation."""
        return self._state

    def data_to_send(self) -> bytes:
        """Returns the data to be sent via the I/O library of choice.

        Also clears the authenticator's buffer.
        """
        data = bytes(self._data_to_send)
        self._data_to_send = bytearray()
        return data

    def receive_data(self, data: bytes) -> None:
        """Processes data received from the proxy server.

        Raises:
            ProtocolError: If the data does not conform with RFC 1961 or the
                GSSAPI context fails. The state becomes MUST_CLOSE.
        """
        if self._state not in (
            GSSAPIState.TOKEN_EXCHANGE,
            GSSAPIState.PROTECTION_NEGOTIATION,
        ):
            raise ProtocolError("Not currently performing GSSAPI negotiation")
        self._buffer += data
        try:
            while self._state in (
                GSSAPIState.TOKEN_EXCHANGE,
                GSSAPIState.PROTECTION_NEGOTIATION,
            ):
                decoded = decode_message(self._buffer)
                if decoded is None:
                    break
                self._handle_message(*decoded)
        except ProtocolError:
            self._state = GSSAPIState.MUST_CLOSE
            raise

    def _handle_message(
        self, message_type: GSSAPIMessageType, token: bytes
    ) -> None:
        if message_type == GSSAPIMessageType.ABORT:
            raise ProtocolError("The server aborted the GSSAPI authentication")
        elif message_type == GSSAPIMessageType.AUTHENTICATION:
            if self._state != GSSAPIState.TOKEN_EXCHANGE:
                raise ProtocolError("Unexpected GSSAPI authentication token")
            self._step(token)
        elif message_type == GSSAPIMessageType.PROTECTION_NEGOTIATION:
            if self._state != GSSAPIState.PROTECTION_NEGOTIATION:
                raise ProtocolError(
                    "Unexpected GSSAPI protection level negotiation message"
                )
            self._negotiate_protection(token)
        else:  # pragma: nocover
            raise ProtocolError("Invalid GSSAPI message type")

    def _step(self, token: bytes) -> None:
        try:
            output_token = self._context.step(token)
        except Exception as exc:
            raise ProtocolError("The GSSAPI context failed to process a token") from exc
        self._data_to_send += encode_message(
            GSSAPIMessageType.AUTHENTICATION, output_token
        )
        if self._context.complete:
            self._state = GSSAPIState.PROTECTION_NEGOTIATION
            try:
                wrapped = self._context.wrap(bytes([self._min_protection]))
            except Exception as exc:
                raise ProtocolError(
                    "The GSSAPI context failed to wrap the protection level"
                ) from exc
            self._data_to_send += encode_message(
                GSSAPIMessageType.PROTECTION_NEGOTIATION, wrapped
            )

    def _negotiate_protection(self, token: bytes) -> None:
        try:
            plaintext = self._context.unwrap(token)
        except Exception as exc:
            raise ProtocolError(
                "The protection level negotiation message failed verification"
            ) from exc
        if len(plaintext) != 1:
            raise ProtocolError("Malformed protection level negotiation message")
        level = plaintext[0]
        if level == GSSAPIProtectionLevel.NONE:
            raise ProtocolError("The server found no acceptable protection level")
        if level > GSSAPIProtectionLevel.SELECTIVE:
            raise ProtocolError("Unknown protection level selected by the server")
        if level < self._min_protection:
            raise ProtocolError(
                "The negotiated protection level is below the required minimum"
            )
        self.protection_level = GSSAPIProtectionLevel(level)
        self._state = GSSAPIState.AUTHENTICATED
