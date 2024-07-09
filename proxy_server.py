import socket
import sys
import ssl
from http.server import HTTPServer
from socketserver import ThreadingMixIn
from proxy_handler import ProxyRequestHandler

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    # address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)

def run_server(args):
    protocol = "HTTP/1.1"
    server_address = (args.bind, args.port)
    ProxyRequestHandler.protocol_version = protocol
    httpd = ThreadingHTTPServer(server_address, ProxyRequestHandler)
    sa = httpd.socket.getsockname()
    print(f"Serving HTTP Proxy on {sa[0]}:{sa[1]} ...")
    httpd.serve_forever()