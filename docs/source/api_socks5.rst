.. _SOCKS5-API-documentation:

.. currentmodule:: socksio.socks5

SOCKS5 API documentation
====================================

.. autoclass:: SOCKS5Connection
   :members:

.. autoclass:: SOCKS5ServerConnection
   :members:

.. autoclass:: SOCKS5AuthMethodsRequest
   :members: loads, dumps

.. autoclass:: SOCKS5DataReceived
   :members:

.. autoclass:: SOCKS5AuthReply
   :members: loads, dumps

.. autoclass:: SOCKS5UsernamePasswordRequest
   :members: loads, dumps

.. autoclass:: SOCKS5UsernamePasswordReply
   :members: loads, dumps

.. autoclass:: SOCKS5CommandRequest
   :members: from_address, loads, dumps

.. autoclass:: SOCKS5Reply
   :members: from_address, loads, dumps
