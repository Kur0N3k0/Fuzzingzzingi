import gzip
import http.client
import re
import select
import socket
import ssl
import threading
import urllib.parse
import zlib
import os
import time
import json
import mysql.connector
import http.cookies
from subprocess import Popen, PIPE
from http.server import BaseHTTPRequestHandler
from http.client import HTTPMessage
from utils import with_color, parse_qsl, print_info
from config import args, request_handler, response_handler, save_handler, db_config

class ProxyRequestHandler(BaseHTTPRequestHandler):
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        super().__init__(*args, **kwargs)

    def log_error(self, format, *args):
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        host, _ = self.path.split(":", 1)
        if (
            os.path.isfile(args.ca_key)
            and os.path.isfile(args.ca_cert)
            and os.path.isfile(args.cert_key)
            and os.path.isdir(args.cert_dir)
            and (args.domain == "*" or args.domain == host)
        ):
            print("HTTPS mitm enabled, Intercepting...")
            self.connect_intercept()
        else:
            print("HTTPS relay only, NOT Intercepting...")
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(":")[0]
        certpath = os.path.join(args.cert_dir, hostname + ".pem")
        confpath = os.path.join(args.cert_dir, hostname + ".conf")

        with self.lock:
            if not os.path.isfile(certpath):
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
                    category = "IP"
                else:
                    category = "DNS"
                with open(confpath, "w") as f:
                    f.write(
                        "subjectAltName=%s:%s\nextendedKeyUsage=serverAuth\n"
                        % (category, hostname)
                    )
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(
                    [
                        "openssl",
                        "req",
                        "-sha256",
                        "-new",
                        "-key",
                        args.cert_key,
                        "-subj",
                        "/CN=%s" % hostname,
                        "-addext",
                        "subjectAltName=DNS:%s" % hostname,
                    ],
                    stdout=PIPE,
                )
                p2 = Popen(
                    [
                        "openssl",
                        "x509",
                        "-req",
                        "-sha256",
                        "-days",
                        "365",
                        "-CA",
                        args.ca_cert,
                        "-CAkey",
                        args.ca_key,
                        "-set_serial",
                        epoch,
                        "-out",
                        certpath,
                        "-extfile",
                        confpath,
                    ],
                    stdin=p1.stdout,
                    stderr=PIPE,
                )
                p2.communicate()

        self.send_response(200, "Connection Established")
        self.end_headers()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(certpath, args.cert_key)
        try:
            self.connection = context.wrap_socket(self.connection, server_side=True)
        except ssl.SSLEOFError:
            print("Handshake refused by client, maybe SSL pinning?")
            return
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get("Proxy-Connection", "")
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != "close":
            self.close_connection = False
        else:
            self.close_connection = True

    def connect_relay(self):
        address = self.path.split(":", 1)
        address = (address[0], int(address[1]) or 443)
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception:
            self.send_error(502)
            return
        self.send_response(200, "Connection Established")
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = False
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = True
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == "http://fuzzingzzingi.cert/":
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get("Content-Length", 0))
        req_body = self.rfile.read(content_length) if content_length else b""

        if req.path[0] == "/":
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers["Host"], req.path)
            else:
                req.path = "http://%s%s" % (req.headers["Host"], req.path)

        if request_handler is not None:
            req_body_modified = request_handler(req, req_body.decode())
            if req_body_modified is False:
                self.send_error(403)
                return
            if req_body_modified is not None:
                req_body = req_body_modified.encode()
                req.headers["Content-Length"] = str(len(req_body))

        u = urllib.parse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + "?" + u.query if u.query else u.path)
        assert scheme in ("http", "https")
        if netloc:
            req.headers["Host"] = netloc
        req.headers = self.filter_headers(req.headers)

        origin = (scheme, netloc)
        try:
            if origin not in self.tls.conns:
                if scheme == "https":
                    self.tls.conns[origin] = http.client.HTTPSConnection(
                        netloc, timeout=self.timeout
                    )
                else:
                    self.tls.conns[origin] = http.client.HTTPConnection(
                        netloc, timeout=self.timeout
                    )
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()

            cache_control = res.headers.get("Cache-Control", "")
            if "Content-Length" not in res.headers and "no-store" in cache_control:
                if response_handler is not None:
                    response_handler(req, req_body, res, "")
                res.headers = self.filter_headers(res.headers)
                self.relay_streaming(res)
                if save_handler is not None:
                    with self.lock:
                        save_handler(req, req_body, res, "")
                return

            res_body = res.read()
        except Exception:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        if response_handler is not None:
            content_encoding = res.headers.get("Content-Encoding", "identity")
            res_body_plain = self.decode_content_body(res_body, content_encoding)
            res_body_modified = response_handler(req, req_body, res, res_body_plain)
            if res_body_modified is False:
                self.send_error(403)
                return
            if res_body_modified is not None:
                res_body = self.encode_content_body(res_body_modified, content_encoding)
                res.headers["Content-Length"] = str(len(res_body))

        res.headers = self.filter_headers(res.headers)

        self.send_response_only(res.status, res.reason)
        for k, v in res.headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        if save_handler is not None:
            content_encoding = res.headers.get("Content-Encoding", "identity")
            res_body_plain = self.decode_content_body(res_body, content_encoding)
            with self.lock:
                save_handler(req, req_body, res, res_body_plain)
                self.save_to_database(req, req_body, res, res_body_plain)

    do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_GET

    def filter_headers(self, headers: HTTPMessage) -> HTTPMessage:
        hop_by_hop = (
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        )
        for k in hop_by_hop:
            del headers[k]

        if "Accept-Encoding" in headers:
            ae = headers["Accept-Encoding"]
            filtered_encodings = [
                x
                for x in re.split(r",\s*", ae)
                if x in ("identity", "gzip", "x-gzip", "deflate")
            ]
            headers["Accept-Encoding"] = ", ".join(filtered_encodings)

        return headers

    def encode_content_body(self, text: bytes, encoding: str) -> bytes:
        if encoding == "identity":
            data = text
        elif encoding in ("gzip", "x-gzip"):
            data = gzip.compress(text)
        elif encoding == "deflate":
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data: bytes, encoding: str) -> bytes:
        if encoding == "identity":
            text = data
        elif encoding in ("gzip", "x-gzip"):
            text = gzip.decompress(data)
        elif encoding == "deflate":
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(args.ca_cert, "rb") as f:
            data = f.read()

        self.send_response(200, "OK")
        self.send_header("Content-Type", "application/x-x509-ca-cert")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def relay_streaming(self, res):
        self.send_response_only(res.status, res.reason)
        for k, v in res.headers.items():
            self.send_header(k, v)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    def save_to_database(self, req, req_body, res, res_body):
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        try:
            query = """
            INSERT INTO requests (url, is_https, parameters, method, protocol_version, 
                                  headers, cookies, response_status, response_headers, 
                                  response_body, ssl_info)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            is_https = isinstance(req.connection, ssl.SSLSocket)
            url = req.path
            parameters = json.dumps(dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(req.path).query)))
            headers = json.dumps(dict(req.headers))
            cookies = json.dumps(dict(http.cookies.SimpleCookie(req.headers.get('Cookie'))))
            response_headers = json.dumps(dict(res.headers))
            
            ssl_info = None
            if is_https:
                ssl_info = json.dumps({
                    'version': req.connection.version(),
                    'cipher': req.connection.cipher(),
                })

            values = (
                url, is_https, parameters, req.command, req.request_version,
                headers, cookies, res.status, response_headers, res_body, ssl_info
            )

            cursor.execute(query, values)
            conn.commit()

        except Exception as e:
            print(f"Error saving to database: {e}")
        finally:
            cursor.close()
            conn.close()
