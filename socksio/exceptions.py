class SOCKSError(Exception):
    """Generic exception for when something goes wrong"""


class ProtocolError(SOCKSError):
    pass


class FragmentationNotSupported(SOCKSError):
    """Raised when a fragmented UDP datagram is received or built.

    SOCKS5 UDP datagram fragmentation (a non-zero FRAG field) is not
    supported. Fragments must not be treated as complete payloads.
    """
