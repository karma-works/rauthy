#!/usr/bin/env python3
"""Check the installed builder TLS library and certificate verification using loopback HTTPS."""

import http.server
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request

from builder_openssl import VERSION


def main():
    assert ssl.OPENSSL_VERSION.startswith(f"OpenSSL {VERSION} "), ssl.OPENSSL_VERSION
    default_context = ssl.create_default_context()
    assert default_context.cert_store_stats()["x509_ca"] > 0
    with tempfile.TemporaryDirectory(prefix="rauthy-builder-tls-test-") as temporary:
        cert, key = (Path(temporary) / name for name in ("cert.pem", "key.pem"))
        subprocess.run(
            ["/usr/local/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc",
             "-sha256", "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost", "-keyout", str(key), "-out", str(cert)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        trusted_context = ssl.create_default_context(cafile=cert)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trusted_context)
        )
        port = server.server_port
        try:
            with opener.open(f"https://localhost:{port}/", timeout=10) as response:
                assert response.status == 200
            for host, context in (("localhost", default_context), ("127.0.0.1", trusted_context)):
                rejected = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
                )
                try:
                    rejected.open(f"https://{host}:{port}/", timeout=10)
                except urllib.error.URLError as error:
                    assert isinstance(error.reason, ssl.SSLCertVerificationError), error
                else:
                    raise AssertionError("TLS accepted an untrusted certificate or wrong hostname")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)
    print(ssl.OPENSSL_VERSION, ssl.get_default_verify_paths())
    print("Builder HTTPS: trusted certificate accepted; untrusted CA and wrong hostname rejected")


if __name__ == "__main__":
    main()
