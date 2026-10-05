"""A fake GSSAPI context with inspectable call counts, for tests only."""

import typing

from socksio.gssapi import GSSAPIMessageType


def tag(data: bytes) -> bytes:
    return bytes([sum(data) % 256, len(data) % 256])


def server_wrap(data: bytes) -> bytes:
    return data + tag(data)


def server_unwrap(token: bytes) -> bytes:
    data, received_tag = token[:-2], token[-2:]
    assert received_tag == tag(data)
    return data


def server_message(message_type: GSSAPIMessageType, token: bytes) -> bytes:
    return b"\x01" + bytes([message_type]) + len(token).to_bytes(2, "big") + token


class FakeGSSError(Exception):
    pass


class FakeGSSAPIContext:
    """A fake GSSAPI context with inspectable call counts.

    Completes after ``steps_to_complete`` calls to ``step``. Wrapping appends
    a verifiable two-byte authentication tag to the data.
    """

    def __init__(self, steps_to_complete: int = 1) -> None:
        self.steps_to_complete = steps_to_complete
        self.complete = False
        self.step_calls = 0
        self.wrap_calls = 0
        self.unwrap_calls = 0
        self.stepped_tokens: typing.List[bytes] = []
        self.unwrapped: typing.List[bytes] = []

    def step(self, token: bytes) -> bytes:
        self.step_calls += 1
        self.stepped_tokens.append(token)
        if self.step_calls >= self.steps_to_complete:
            self.complete = True
        return b"client-token-%d" % self.step_calls

    def wrap(self, data: bytes) -> bytes:
        self.wrap_calls += 1
        return server_wrap(data)

    def unwrap(self, token: bytes) -> bytes:
        self.unwrap_calls += 1
        if len(token) < 2:
            raise FakeGSSError("token too short")
        data, received_tag = token[:-2], token[-2:]
        if received_tag != tag(data):
            raise FakeGSSError("invalid authentication tag")
        self.unwrapped.append(data)
        return data
