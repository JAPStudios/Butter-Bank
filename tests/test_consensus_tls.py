import datetime
import ipaddress
import os
import ssl
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from consensus_network import ConsensusHTTPServer
from engine import ConsensusEngine
from signer import ConsensusSigner


class MutualTlsTransportTests(unittest.TestCase):
    def test_allowlisted_client_certificate_completes_mutual_tls_handshake(self):
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Butter Bank test CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "validator-1")])
        client_cert = (
            x509.CertificateBuilder()
            .subject_name(client_name)
            .issuer_name(ca_name)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ca_path = root / "ca.pem"
            cert_path = root / "validator.pem"
            key_path = root / "validator-key.pem"
            state_path = root / "signer-state.json"
            ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
            cert_path.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(client_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
            if os.name != "nt":
                key_path.chmod(0o600)

            validator_key = ed25519.Ed25519PrivateKey.generate()
            public_key = validator_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ).hex()
            validators = [{"public_key": public_key, "voting_power": 1}]
            signer = ConsensusSigner(validator_key, "tls-test-chain", validators, state_path)
            engine = ConsensusEngine(signer, lambda block: block.get("hash"))
            server = ConsensusHTTPServer(
                engine,
                host="127.0.0.1",
                port=0,
                tls_certfile=str(cert_path),
                tls_keyfile=str(key_path),
                tls_ca_file=str(ca_path),
                tls_client_certfile=str(cert_path),
                tls_client_keyfile=str(key_path),
                tls_peer_fingerprints=[client_cert.fingerprint(hashes.SHA256()).hex()],
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                context = ssl.create_default_context(cafile=str(ca_path))
                context.load_cert_chain(str(cert_path), str(key_path))
                port = server.server.server_address[1]
                request = urllib.request.Request(
                    f"https://127.0.0.1:{port}/consensus/proposal",
                    data=b"{}",
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as response:
                    urllib.request.urlopen(request, timeout=3, context=context)
                # HTTP 400 proves TLS and client-certificate admission succeeded;
                # the empty proposal is deliberately invalid at the application layer.
                self.assertEqual(response.exception.code, 400)
            finally:
                server.shutdown()
                thread.join(3)
                signer.close()


if __name__ == "__main__":
    unittest.main()
