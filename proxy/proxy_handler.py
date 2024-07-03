import os
import re
import socket
import ssl
import select
import logging
import urllib.parse
import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler
from savepacket import save_packet_to_db
from utils import decode_content_body, encode_content_body, filter_headers, with_color

class CustomProxyRequestHandler(BaseHTTPRequestHandler):
    lock = threading.Lock()
    packet_storage = []

    def __init__(self, *args, server_args=None, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        self.server_args = server_args
        super().__init__(*args, **kwargs)

    def log_error(self, format, *args):
        if isinstance(args[0], socket.timeout):
            logging.warning("Socket timeout occurred")
        else:
            logging.error(format % args)

    def do_CONNECT(self):
        handle_connect(self)

    def do_GET(self):
        handle_get(self)

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def connect_intercept(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        cert_dir = os.path.join(current_dir, self.server_args.cert_dir)
        domain = self.server_args.domain

        ca_cert = os.path.join(cert_dir, "ca-cert.pem")
        cert_file = os.path.join(cert_dir, f"{domain}-cert.pem")
        key_file = os.path.join(cert_dir, f"{domain}-key.pem")

        if not all(os.path.exists(f) for f in [ca_cert, cert_file, key_file]):
            logging.error(f"Certificate files not found. Please run with --make-certs flag first.")
            self.send_error(500, "Certificate files not found")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        try:
            client_connection = self.connection
            client_address = self.client_address

            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            context.set_ciphers('HIGH:!aNULL:!MD5')

            ssl_connection = context.wrap_socket(client_connection, server_side=True)
            logging.debug("SSL handshake completed successfully")

            hostname = self.path.split(':')[0]
            port = int(self.path.split(':')[1]) if ':' in self.path else 443

            upstream_socket = socket.create_connection((hostname, port))
            upstream_ssl = ssl.create_default_context().wrap_socket(upstream_socket, server_hostname=hostname)

            self._read_write_data(ssl_connection, upstream_ssl)

        except Exception as e:
            logging.error(f"Error in connect_intercept: {e}", exc_info=True)
        finally:
            if 'ssl_connection' in locals():
                ssl_connection.close()
            if 'upstream_ssl' in locals():
                upstream_ssl.close()

    def _read_write_data(self, client, server):
        conns = [client, server]
        try:
            while True:
                r, w, e = select.select(conns, [], conns, 10)
                if e:
                    break
                for readable in r:
                    other = conns[1] if readable is conns[0] else conns[0]
                    try:
                        data = readable.recv(8192)
                        if not data:
                            return
                        other.sendall(data)
                        logging.debug(f"Data transferred: {len(data)} bytes")
                        packet = {
                            'url': self.path,
                            'parameters': {},
                            'method': self.command,
                            'protocol_version': self.request_version,
                            'headers': dict(self.headers),
                            'cookies': self.headers.get('Cookie', {}),
                            'response_body': data.decode('ISO-8859-1', errors='replace')
                        }
                        logging.debug(f"Captured packet: {packet}")
                        CustomProxyRequestHandler.packet_storage.append(packet)
                        self.save_packets()
                    except ssl.SSLWantReadError:
                        continue
                    except Exception as e:
                        logging.error(f"Error during data transfer: {e}", exc_info=True)
                        return
        except Exception as e:
            logging.error(f"Error in _read_write_data: {e}", exc_info=True)
        finally:
            self.save_packets()

    def save_packets(self):
        if CustomProxyRequestHandler.packet_storage:
            logging.debug(f"Attempting to save {len(CustomProxyRequestHandler.packet_storage)} packets")
            save_packet_to_db(CustomProxyRequestHandler.packet_storage)
            CustomProxyRequestHandler.packet_storage.clear()

    def connect_relay(self):
        host, port = self.path.split(":", 1)
        port = int(port)
        try:
            remote_socket = socket.create_connection((host, port))
        except Exception as e:
            logging.error(f"Error connecting to remote server: {e}", exc_info=True)
            self.send_error(502)
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        self._read_write_data(self.connection, remote_socket)

    def relay_streaming(self, response):
        self.send_response_only(response.status, response.reason)
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                CustomProxyRequestHandler.packet_storage.append(chunk)
            self.wfile.flush()
        except socket.error:
            pass

def handle_connect(proxy_handler):
    host, _ = proxy_handler.path.split(":", 1)
    if (proxy_handler.server.args.domain == "*" or proxy_handler.server.args.domain == host):
        proxy_handler.connect_intercept()
    else:
        proxy_handler.connect_relay()

def handle_get(proxy_handler):
    request = proxy_handler
    content_length = int(request.headers.get("Content-Length", 0))
    request_body = proxy_handler.rfile.read(content_length) if content_length else b""

    if request.path[0] == "/":
        if isinstance(proxy_handler.connection, ssl.SSLSocket):
            request.path = "https://%s%s" % (request.headers["Host"], request.path)
        else:
            request.path = "http://%s%s" % (request.headers["Host"], request.path)

    parsed_url = urllib.parse.urlsplit(request.path)
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc
    path = parsed_url.path + "?" + parsed_url.query if parsed_url.query else parsed_url.path
    assert scheme in ("http", "https")
    if netloc:
        request.headers["Host"] = netloc
    request.headers = filter_headers(request.headers)

    origin = (scheme, netloc)
    try:
        if origin not in proxy_handler.tls.conns:
            if scheme == "https":
                proxy_handler.tls.conns[origin] = http.client.HTTPSConnection(
                    netloc, timeout=proxy_handler.timeout
                )
            else:
                proxy_handler.tls.conns[origin] = http.client.HTTPConnection(
                    netloc, timeout=proxy_handler.timeout
                )
        connection = proxy_handler.tls.conns[origin]
        connection.request(proxy_handler.command, path, request_body, dict(request.headers))
        response = connection.getresponse()

        cache_control = response.headers.get("Cache-Control", "")
        if "Content-Length" not in response.headers and "no-store" in cache_control:
            response.headers = filter_headers(response.headers)
            proxy_handler.relay_streaming(response)
            return

        response_body = response.read()
    except Exception as e:
        logging.error(f"Error in handle_get: {e}", exc_info=True)
        if origin in proxy_handler.tls.conns:
            del proxy_handler.tls.conns[origin]
        proxy_handler.send_error(502)
        return

    response_body_plain = decode_content_body(response_body, response.headers.get("Content-Encoding", "identity"))
    response_body = encode_content_body(response_body_plain, response.headers.get("Content-Encoding", "identity"))
    response.headers["Content-Length"] = str(len(response_body))

    response.headers = filter_headers(response.headers)

    proxy_handler.send_response_only(response.status, response.reason)
    for key, value in response.headers.items():
        proxy_handler.send_header(key, value)
    proxy_handler.end_headers()
    proxy_handler.wfile.write(response_body)
    proxy_handler.wfile.flush()

    packet = {
        'url': request.path,
        'parameters': urllib.parse.parse_qs(parsed_url.query),
        'method': request.command,
        'protocol_version': request.request_version,
        'headers': dict(request.headers),
        'cookies': request.headers.get('Cookie', {}),
        'response_body': response_body_plain.decode('ISO-8859-1') if response_body_plain else ""
    }
    CustomProxyRequestHandler.packet_storage.append(packet)

    logging.debug(f"Captured GET packet: {packet}")
    proxy_handler.save_packets()

    display_info(request, request_body, response, response_body_plain)

def display_info(request, request_body, response, response_body):
    request_header_text = "%s %s %s\n%s" % (
        request.command,
        request.path,
        request.request_version,
        request.headers,
    )
    version_table = {10: "HTTP/1.0", 11: "HTTP/1.1"}
    response_header_text = "%s %d %s\n%s" % (
        version_table[response.version],
        response.status,
        response.reason,
        response.headers,
    )

    print(with_color(33, request_header_text))

    parsed_url = urllib.parse.urlsplit(request.path)
    if parsed_url.query:
        query_text = urllib.parse.parse_qsl(parsed_url.query)
        print(with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text))

    cookie_header = request.headers.get("Cookie", "")
    if cookie_header:
        cookie_header = urllib.parse.parse_qsl(re.sub(r";\s*", "&", cookie_header))
        print(with_color(32, "==== COOKIE ====\n%s\n" % cookie_header))

    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("basic"):
        token = authorization.split()[1].decode("base64")
        print(with_color(31, "==== BASIC AUTH ====\n%s\n" % token))

    if request_body:
        request_body_text = None
        content_type = request.headers.get("Content-Type", "")

        if content_type.startswith("application/x-www-form-urlencoded"):
            request_body_text = urllib.parse.parse_qsl(request_body)
        elif content_type.startswith("application/json"):
            try:
                json_obj = json.loads(request_body)
                json_str = json.dumps(json_obj, indent=2)
                if json_str.count("\n") < 50:
                    request_body_text = json_str
                else:
                    lines = json_str.splitlines()
                    request_body_text = "%s\n(%d lines)" % (
                        "\n".join(lines[:50]), len(lines)
                    )
            except ValueError:
                request_body_text = request_body
        elif len(request_body) < 1024:
            request_body_text = request_body

        if request_body_text:
            print(with_color(32, "==== REQUEST BODY ====\n%s\n" % request_body_text))

    print(with_color(36, response_header_text))

    cookies = response.headers.get("Set-Cookie")
    if cookies:
        print(with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies))

    if response_body:
        response_body_text = None
        content_type = response.headers.get("Content-Type", "")

        if content_type.startswith("application/json"):
            try:
                json_obj = json.loads(response_body)
                json_str = json.dumps(json_obj, indent=2)
                if json_str.count("\n") < 50:
                    response_body_text = json_str
                else:
                    lines = json_str.splitlines()
                    response_body_text = "%s\n(%d lines)" % (
                        "\n".join(lines[:50]), len(lines)
                    )
            except ValueError:
                response_body_text = response_body
        elif content_type.startswith("text/html"):
            match = re.search(rb"<title[^>]*>\s*([^<]+?)\s*</title>", response_body, re.I)
            if match:
                print(with_color(32, "==== HTML TITLE ====\n%s\n" % match.group(1).decode()))
        elif content_type.startswith("text/") and len(response_body) < 1024:
            response_body_text = response_body

        if response_body_text:
            print(with_color(32, "==== RESPONSE BODY ====\n%s\n" % response_body_text))
