"""Ephemeral certificate authority of the local stack.

Writes, into the directory named by CERTS_DIR (a Docker volume, never the
repository):

    ca.crt                the trust anchor
    <name>.crt/.key/.pem  one server certificate per name of CERT_NAMES
                          (.pem holds certificate then key, as HAProxy expects)
    lab-key               the shared X-Lab-Key of the bench

The private key of the authority is never written: once the server
certificates are signed it is dropped, so nothing else can be issued under
this anchor. The run is idempotent: an already filled directory is left
untouched, so that running components keep matching certificates. Removing
the volume (`make local-down`) discards everything.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import secrets
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

LIFETIME = datetime.timedelta(days=30)  # bench setting
LAB_KEY_BYTES = 32  # hex-encoded: the 64 characters the echo backend requires


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def generate(directory: Path, names: list[str]) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before, not_after = now - datetime.timedelta(minutes=5), now + LIFETIME

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = _name("pqc-oidc-bench ephemeral local CA")
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    for name in names:
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(_name(name))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(name), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        (directory / f"{name}.crt").write_bytes(certificate_pem)
        (directory / f"{name}.key").write_bytes(_pem(key))
        (directory / f"{name}.pem").write_bytes(certificate_pem + _pem(key))

    (directory / "lab-key").write_text(secrets.token_hex(LAB_KEY_BYTES), encoding="ascii")
    # Written last: its presence marks a complete set.
    (directory / "ca.crt").write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    # The components run under different unprivileged users and all read this
    # volume, which only ever holds this throwaway material.
    for path in directory.iterdir():
        path.chmod(0o644)


def main() -> None:
    directory = Path(os.environ.get("CERTS_DIR", "/certs"))
    names = os.environ.get("CERT_NAMES", "").split()
    if not names:
        sys.exit("CERT_NAMES is empty")
    expected = [directory / "ca.crt", directory / "lab-key"] + [directory / f"{name}.pem" for name in names]
    if all(path.exists() for path in expected):
        print("TLS material already present: left untouched")
        return
    generate(directory, names)
    print(f"generated an ephemeral CA and {len(names)} server certificates")


if __name__ == "__main__":
    main()
