"""CVE-2026-63374: TLS peer names must reach SSL as IDNA2008 A-labels."""

from types import SimpleNamespace

import pytest
from anyio.streams.tls import TLSStream


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No user database needed for a dependency contract."""


@pytest.mark.parametrize("hostname,expected", [
    ("fa\u00df.example", b"xn--fa-hia.example"),
    ("example.com", b"example.com"),
    ("xn--fa-hia.example", b"xn--fa-hia.example"),
])
async def test_tlsstream_passes_idna2008_name_to_ssl(hostname, expected):
    captured = []

    class Context:
        def wrap_bio(self, incoming, outgoing, server_side, server_hostname, session):
            captured.append(server_hostname)
            return SimpleNamespace(do_handshake=lambda: None)

    await TLSStream.wrap(object(), hostname=hostname, ssl_context=Context())
    assert captured == [expected]
    if "\u00df" in hostname:
        assert captured[0] != hostname.encode("idna")  # IDNA2003 aliases this to fass.example.
