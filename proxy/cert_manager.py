import os
from OpenSSL import crypto

def generate_ca_cert(cert_dir):
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    ca_cert = crypto.X509()
    ca_cert.get_subject().CN = "Custom CA"
    ca_cert.set_serial_number(1000)
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 years
    ca_cert.set_issuer(ca_cert.get_subject())
    ca_cert.set_pubkey(ca_key)
    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
        crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])
    ca_cert.sign(ca_key, "sha256")

    with open(os.path.join(cert_dir, "ca-key.pem"), "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
    with open(os.path.join(cert_dir, "ca-cert.pem"), "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))

def generate_cert(cert_dir, domain):
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(os.path.join(cert_dir, "ca-cert.pem"), "rb").read())
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(os.path.join(cert_dir, "ca-key.pem"), "rb").read())

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = domain
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # 1 year
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)
    
    alt_name = f"DNS:{domain}"
    if domain.startswith("*."):
        alt_name += f", DNS:{domain[2:]}"
    
    cert.add_extensions([
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
        crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
        crypto.X509Extension(b"subjectAltName", False, alt_name.encode()),
    ])
    cert.sign(ca_key, "sha256")

    with open(os.path.join(cert_dir, f"{domain}-key.pem"), "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    with open(os.path.join(cert_dir, f"{domain}-cert.pem"), "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def generate_certs(cert_dir, domain):
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    generate_ca_cert(cert_dir)
    generate_cert(cert_dir, domain)

    print(f"Certificates generated at {cert_dir}")
    print(f"Generated certificates for domain: {domain}")
    print("Important: Add the generated CA certificate (ca-cert.pem) to your browser's trusted root certificates.")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate SSL certificates for proxy")
    parser.add_argument("--cert-dir", default="certs", help="Directory to store certificates")
    parser.add_argument("--domain", required=True, help="Domain to generate certificate for")
    
    args = parser.parse_args()
    
    generate_certs(args.cert_dir, args.domain)
