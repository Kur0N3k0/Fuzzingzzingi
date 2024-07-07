import os
import ssl
from subprocess import Popen
import shutil
import glob

def create_ssl_context(certpath, keypath):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certpath, keypath)
    return context

def make_certs(args):
    Popen(["openssl", "genrsa", "-out", args.ca_key, "2048"]).communicate()
    Popen([
        "openssl", "req", "-new", "-x509", "-days", "3650", "-key", args.ca_key,
        "-sha256", "-out", args.ca_cert, "-subj", "/CN=Proxy3 CA"
    ]).communicate()
    Popen(["openssl", "genrsa", "-out", args.cert_key, "2048"]).communicate()
    os.makedirs(args.cert_dir, exist_ok=True)
    for old_cert in glob.glob(os.path.join(args.cert_dir, "*.pem")):
        os.remove(old_cert)

def make_example():
    example_file = os.path.join(os.path.dirname(__file__), "examples/example.py")
    shutil.copy(example_file, "proxy3_handlers_example.py")
