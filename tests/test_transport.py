import asyncio
import ssl

import pytest

from scripts.apple_probe import VerifiedHttpSession


def test_authentication_transport_requires_verified_tls():
    transport = VerifiedHttpSession()
    assert transport.tls_context.check_hostname is True
    assert transport.tls_context.verify_mode == ssl.CERT_REQUIRED
    with pytest.raises(ValueError, match="HTTPS"):
        asyncio.run(transport.request("POST", "http://gsa.apple.com/grandslam/GsService2"))


def test_auth_requests_use_new_tls_connections_and_keep_cookies(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    import ipaddress
    from aiohttp import web
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import scripts.apple_probe as probe

    monkeypatch.setattr(probe, "PRIVATE", tmp_path)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .sign(key, hashes.SHA256()))
    certfile, keyfile = tmp_path / "cert.pem", tmp_path / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    async def run():
        peers, cookies = [], []
        async def handle(request):
            peers.append(request.transport.get_extra_info("peername"))
            cookies.append(request.cookies.get("session"))
            response = web.Response(text="ok")
            response.set_cookie("session", "synthetic-session", secure=True)
            return response
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certfile, keyfile)
        app = web.Application()
        app.router.add_get("/", handle)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=server_context)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        transport = VerifiedHttpSession()
        transport.tls_context = ssl.create_default_context(cafile=str(certfile))
        try:
            for _ in range(4):
                response = await transport.get(f"https://localhost:{port}/")
                assert response.ok
            assert len(set(peers)) == 4
            assert cookies == [None] + ["synthetic-session"] * 3
        finally:
            await transport.close()
            await runner.cleanup()
        with pytest.raises(RuntimeError, match="closed"):
            await transport._get_session()
    asyncio.run(run())
