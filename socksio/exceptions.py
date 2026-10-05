class SOCKSError(Exception):
    """Generic exception for when something goes wrong"""


class ProtocolError(SOCKSError):
    pass


class SOCKS5UDPNotAssociatedError(SOCKSError):
    """Raised when a UDP association is used without a successful UDP ASSOCIATE."""


class SOCKS5UDPAssociationClosedError(SOCKSError):
    """Raised when a UDP association is used after the control connection is closed.

    A UDP association is only valid as long as the control connection used to
    request it is alive. Once that connection fails or is closed the relay
    must not accept datagrams anymore.
    """


class SOCKS5FragmentNotSupportedError(SOCKSError):
    """Raised when a datagram with a non-zero FRAG field is encountered.

    This version does not support fragmented datagrams.
    """
