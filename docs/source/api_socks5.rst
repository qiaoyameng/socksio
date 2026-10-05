.. _SOCKS5-API-documentation:

.. currentmodule:: socksio.socks5

SOCKS5 API documentation
====================================

.. autoclass:: SOCKS5Connection
   :members:

.. autoclass:: SOCKS5AuthMethodsRequest
   :members: dumps

.. autoclass:: SOCKS5AuthReply
   :members: loads

.. autoclass:: SOCKS5UsernamePasswordRequest
   :members: dumps

.. autoclass:: SOCKS5UsernamePasswordReply
   :members: loads

.. autoclass:: GSSAPIContext
   :members: complete, step, wrap, unwrap

.. autoclass:: SOCKS5GSSAPIProtectionLevel
   :members:

.. autoclass:: SOCKS5GSSAPIRequest
   :members: dumps

.. autoclass:: SOCKS5GSSAPIReply
   :members: loads

.. autoclass:: SOCKS5GSSAPIProtectionRequest
   :members: dumps

.. autoclass:: SOCKS5GSSAPIProtectionReply
   :members: loads

.. autoclass:: SOCKS5CommandRequest
   :members: from_address, dumps

.. autoclass:: SOCKS5Reply
   :members: loads
