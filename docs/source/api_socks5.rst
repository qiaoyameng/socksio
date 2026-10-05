.. _SOCKS5-API-documentation:

.. currentmodule:: socksio.socks5

SOCKS5 API documentation
====================================

.. autoclass:: SOCKS5Connection
   :members:

.. autoclass:: SOCKS5ServerConnection
   :members:

.. autoclass:: SOCKS5AuthMethodsReceived

.. autoclass:: SOCKS5UsernamePasswordReceived

.. autoclass:: SOCKS5CommandReceived

.. autoclass:: SOCKS5DataReceived

.. autoclass:: SOCKS5AuthMethodsRequest
   :members: dumps

.. autoclass:: SOCKS5AuthReply
   :members: loads, dumps

.. autoclass:: SOCKS5UsernamePasswordRequest
   :members: dumps

.. autoclass:: SOCKS5UsernamePasswordReply
   :members: loads, dumps

.. autoclass:: SOCKS5CommandRequest
   :members: from_address, dumps

.. autoclass:: SOCKS5Reply
   :members: loads, dumps
