"""Gestión de la CA raíz y certificados de host para MITM HTTPS."""
from __future__ import annotations

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_CA_DIR = os.path.join(os.path.expanduser("~"), ".miniburp")
CA_CERT_FILE = os.path.join(_CA_DIR, "ca.crt")
_CA_KEY_FILE = os.path.join(_CA_DIR, "ca.key")
_CERT_DIR = os.path.join(_CA_DIR, "certs")


def ensure_ca():
    """Carga o genera la CA raíz. Seguro para llamar desde cualquier hilo."""
    os.makedirs(_CA_DIR, exist_ok=True)
    os.makedirs(_CERT_DIR, exist_ok=True)

    if os.path.exists(_CA_KEY_FILE) and os.path.exists(CA_CERT_FILE):
        with open(_CA_KEY_FILE, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_FILE, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return key, cert

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MiniBurp CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MiniBurp"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    with open(_CA_KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(CA_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key, cert


def make_host_cert(hostname: str, ca_key, ca_cert) -> tuple[str, str]:
    """Devuelve (cert_path, key_path) para el hostname, generando si hace falta."""
    safe = hostname.replace("*", "_").replace(":", "_")
    cert_path = os.path.join(_CERT_DIR, f"{safe}.crt")
    key_path = os.path.join(_CERT_DIR, f"{safe}.key")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        # Cadena completa: leaf + CA para que Chrome valide la cadena.
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path
