import re
from collections import deque
from io import BytesIO
from typing import Deque, Dict, List, Optional, Tuple

from twisted.internet import defer
from twisted.internet.base import ReactorBase
from twisted.internet.defer import Deferred
from twisted.internet.endpoints import HostnameEndpoint
from twisted.internet.protocol import Protocol
from twisted.internet.tcp import Client as TxClient
from twisted.python.failure import Failure
from twisted.web._newclient import HTTP11ClientProtocol
from twisted.web.client import URI, BrowserLikePolicyForHTTPS, _HTTP11ClientFactory, _StandardEndpointFactory
from twisted.web.error import SchemeNotSupported

from scrapy.core.downloader.contextfactory import AcceptableProtocolsContextFactory
from scrapy.core.downloader.handlers.http11 import tunnel_request_data, TunnelError
from scrapy.core.http2.protocol import H2ClientProtocol, H2ClientFactory
from scrapy.http.request import Request
from scrapy.settings import Settings
from scrapy.spiders import Spider
from scrapy.utils.python import to_bytes


class EmptyResponseReceiver(Protocol):
    pass


class H2ConnectionPool:
    def __init__(self, reactor: ReactorBase, settings: Settings) -> None:
        self._reactor = reactor
        self.settings = settings

        # Store a dictionary which is used to get the respective
        # H2ClientProtocolInstance using the  key as Tuple(scheme, hostname, port)
        self._connections: Dict[Tuple, H2ClientProtocol] = {}

        # Save all requests that arrive before the connection is established
        self._pending_requests: Dict[Tuple, Deque[Deferred]] = {}

    def get_connection(
        self,
        key: Tuple, uri: URI,
        endpoint: HostnameEndpoint,
        context_factory: AcceptableProtocolsContextFactory,
        connect_conf: Tuple = None
    ) -> Deferred:
        if key in self._pending_requests:
            # Received a request while connecting to remote
            # Create a deferred which will fire with the H2ClientProtocol
            # instance
            d = Deferred()
            self._pending_requests[key].append(d)
            return d

        # Check if we already have a connection to the remote
        conn = self._connections.get(key, None)
        if conn:
            # Return this connection instance wrapped inside a deferred
            return defer.succeed(conn)

        # No connection is established for the given URI
        return self._new_connection(key, uri, endpoint, context_factory, connect_conf)

    def _tunnel_connect(
        self,
        uri: URI, endpoint: HostnameEndpoint,
        context_factory: AcceptableProtocolsContextFactory,
        connect_conf: Tuple, conn_lost_deferred: Deferred
    ) -> Deferred:
        """
        Used to establish a SSL Tunnel via CONNECT. Follows the steps below:
        1. Establishes a connection to endpoint via HTTP/1.1
        2. Send CONNECT request
        3. If Response to CONNECT request is 200 then go to 4 else raises TunnelError
        4. Use the socket instance (transport) to create a H2ClientProtocol instance (proxy)
        Arguments:
            uri -- URI of the remote to which the HTTP/2 connection via proxy is made
            endpoint -- Endpoint to the proxy to which HTTP/1.1 connection is made and
                CONNECT request is sent
            connect_conf -- Tuple having (proxy_host, proxy_port, proxy_auth), where proxy_auth is
                the 'Proxy-Authorization' header
        Returns:
            Deferred which fires with the H2ClientProtocol instance
            else calls the errback with TunnelError when CONNECT request
            returns with status code != 200
        """
        proxy_host, proxy_port, proxy_auth = connect_conf
        host_value = to_bytes(uri.host, encoding='ascii') + b':' + to_bytes(str(uri.port))
        response_regex = re.compile(br'HTTP/1\.. (?P<status>\d{3})(?P<reason>.{,32})')

        tunnel_d = Deferred()

        def quiescent_callback(_):
            """Called when CONNECT request is completed
            No need to use this method"""
            print(_)

        connect_data_buffer = BytesIO()

        def receive_connect_data(data: bytes, protocol: HTTP11ClientProtocol) -> None:
            connect_data_buffer.write(data)
            if b'\r\n\r\n' not in connect_data_buffer.getvalue():
                return

            response = response_regex.match(connect_data_buffer.getvalue())
            if response and int(response.group('status')) == 200:
                assert isinstance(protocol.transport, TxClient)

                ssl_options = context_factory.creatorForNetloc(uri.host, uri.port)
                protocol.transport.startTLS(ssl_options)

                h2_protocol = H2ClientProtocol(uri, self.settings, conn_lost_deferred)
                protocol.transport.protocol.wrappedProtocol = h2_protocol
                h2_protocol.makeConnection(protocol.transport)
                tunnel_d.callback(h2_protocol)
            else:
                if response:
                    extra = {
                        'status': int(response.group('status')),
                        'reason': response.group('reason').strip()
                    }
                else:
                    extra = data[:32]
                tunnel_d.errback(TunnelError(uri.host, uri.port, extra))

            print(connect_data_buffer.getvalue())

        def send_connect_request(protocol: HTTP11ClientProtocol):
            """Send CONNECT request"""
            request = tunnel_request_data(uri.host, uri.port, proxy_auth)
            protocol.transport.write(request)

            def data_received(data: bytes):
                receive_connect_data(data, protocol)

            protocol.dataReceived = data_received

        factory = _HTTP11ClientFactory(quiescent_callback, repr(endpoint))
        conn_d = endpoint.connect(factory)
        conn_d.addCallback(send_connect_request)

        return tunnel_d

    def _new_connection(
        self,
        key: Tuple, uri: URI,
        endpoint: HostnameEndpoint,
        context_factory: AcceptableProtocolsContextFactory,
        connect_conf: Tuple = None
    ) -> Deferred:
        self._pending_requests[key] = deque()

        conn_lost_deferred = Deferred()
        conn_lost_deferred.addCallback(self._remove_connection, key)

        if connect_conf:
            conn_d = self._tunnel_connect(uri, endpoint, context_factory, connect_conf, conn_lost_deferred)
        else:
            factory = H2ClientFactory(uri, self.settings, conn_lost_deferred)
            conn_d = endpoint.connect(factory)

        conn_d.addCallback(self.put_connection, key)

        d = Deferred()
        self._pending_requests[key].append(d)
        return d

    def put_connection(self, conn: H2ClientProtocol, key: Tuple) -> H2ClientProtocol:
        self._connections[key] = conn

        # Now as we have established a proper HTTP/2 connection
        # we fire all the deferred's with the connection instance
        pending_requests = self._pending_requests.pop(key, None)
        while pending_requests:
            d = pending_requests.popleft()
            d.callback(conn)

        del pending_requests

        return conn

    def _remove_connection(self, errors: List[BaseException], key: Tuple) -> None:
        self._connections.pop(key)

        # Call the errback of all the pending requests for this connection
        pending_requests = self._pending_requests.pop(key, None)
        while pending_requests:
            d = pending_requests.popleft()
            d.errback(errors)

    def close_connections(self) -> None:
        """Close all the HTTP/2 connections and remove them from pool

        Returns:
            Deferred that fires when all connections have been closed
        """
        for conn in self._connections.values():
            conn.transport.abortConnection()


class H2Agent:
    def __init__(
        self,
        reactor: ReactorBase,
        pool: H2ConnectionPool,
        context_factory: BrowserLikePolicyForHTTPS = BrowserLikePolicyForHTTPS(),
        connect_timeout: Optional[float] = None,
        bind_address: Optional[bytes] = None,
    ) -> None:
        self._reactor = reactor
        self._pool = pool
        self._context_factory = AcceptableProtocolsContextFactory(context_factory, acceptable_protocols=[b'h2'])
        self.endpoint_factory = _StandardEndpointFactory(
            self._reactor, self._context_factory, connect_timeout, bind_address
        )
        self.connect_conf = None

    def get_endpoint(self, uri: URI):
        return self.endpoint_factory.endpointForURI(uri)

    def get_key(self, uri: URI) -> Tuple:
        """
        Arguments:
            uri - URI obtained directly from request URL
        """
        return uri.scheme, uri.host, uri.port

    def request(self, request: Request, spider: Spider) -> Deferred:
        uri = URI.fromBytes(bytes(request.url, encoding='utf-8'))
        try:
            endpoint = self.get_endpoint(uri)
        except SchemeNotSupported:
            return defer.fail(Failure())

        key = self.get_key(uri)
        d = self._pool.get_connection(key, uri, endpoint, self._context_factory, self.connect_conf)
        d.addCallback(lambda conn: conn.request(request, spider))
        return d


class ScrapyProxyH2Agent(H2Agent):
    def __init__(
        self,
        reactor: ReactorBase,
        proxy_uri: URI,
        pool: H2ConnectionPool,
        context_factory: BrowserLikePolicyForHTTPS = BrowserLikePolicyForHTTPS(),
        connect_timeout: Optional[float] = None,
        bind_address: Optional[bytes] = None,
    ) -> None:
        super(ScrapyProxyH2Agent, self).__init__(
            reactor=reactor,
            pool=pool,
            context_factory=context_factory,
            connect_timeout=connect_timeout,
            bind_address=bind_address,
        )
        self._proxy_uri = proxy_uri

    def get_endpoint(self, uri: URI):
        return self.endpoint_factory.endpointForURI(self._proxy_uri)

    def get_key(self, uri: URI) -> Tuple:
        """We use the proxy uri instead of uri obtained from request url"""
        return "http-proxy", self._proxy_uri.host, self._proxy_uri.port

class ScrapyTunnelingH2Agent(H2Agent):
    def __init__(
        self, reactor: ReactorBase,
        proxy_uri: URI, proxy_conf: Tuple,
        pool: H2ConnectionPool,
        context_factory=BrowserLikePolicyForHTTPS(),
        connect_timeout: Optional[float] = None, bind_address: Optional[bytes] = None
    ) -> None:
        super(ScrapyTunnelingH2Agent, self).__init__(
            reactor=reactor,
            pool=pool,
            context_factory=context_factory,
            connect_timeout=connect_timeout,
            bind_address=bind_address
        )
        self.proxy_uri = proxy_uri
        self.connect_conf = proxy_conf

    def get_endpoint(self, uri: URI):
        return self.endpoint_factory.endpointForURI(self.proxy_uri)

    def get_key(self, uri: URI) -> Tuple:
        key = super(ScrapyTunnelingH2Agent, self).get_key(uri)
        return key + self.connect_conf
