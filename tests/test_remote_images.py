from __future__ import annotations

import socket

import pytest

from imapledger.message import RemoteImageRef
from imapledger.remote_images import RemoteImageError, RemoteImageLoader


class _FakeResponse:
    def __init__(self, status=200, *, headers=None, body=b"image-data"):
        self.status = status
        self.headers = headers or {"Content-Type": "image/png", "Content-Length": str(len(body))}
        self.body = body

    def getheader(self, name):
        return self.headers.get(name)

    def read(self, amount):
        return self.body[:amount]


class _FakeConnection:
    def __init__(self, responses, requests, host, address):
        self.responses = responses
        self.requests = requests
        self.host = host
        self.address = address

    def request(self, method, target, *, headers):
        self.requests.append((self.host, self.address, method, target, headers))

    def getresponse(self):
        return self.responses.pop(0)

    def close(self):
        pass


def _resolver_for(addresses=None, seen=None):
    addresses = addresses or {"images.example": ("8.8.8.8",)}

    def resolve(host, port, *, type):
        seen.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port)) for address in addresses[host]]

    return resolve


def _loader(responses, *, addresses=None, max_image_bytes=100, max_images=6, seen=None):
    requests = []
    connections = []
    resolved = seen if seen is not None else []

    def factory(host, address, **kwargs):
        assert kwargs["connect_timeout"] == 5.0
        assert kwargs["read_timeout"] == 10.0
        connections.append((host, address))
        return _FakeConnection(responses, requests, host, address)

    loader = RemoteImageLoader(
        resolver=_resolver_for(addresses, resolved),
        connection_factory=factory,
        max_image_bytes=max_image_bytes,
        max_images=max_images,
    )
    return loader, requests, connections, resolved


def test_fetch_uses_pinned_public_dns_and_sends_no_credentials_or_referrer():
    loader, requests, connections, resolved = _loader([_FakeResponse()])

    content_type, data = loader.fetch("https://images.example/picture.png?token=secret")

    assert content_type == "image/png"
    assert data == b"image-data"
    assert resolved == ["images.example"]
    assert connections == [("images.example", "8.8.8.8")]
    host, address, method, target, headers = requests[0]
    assert (host, address, method, target) == (
        "images.example",
        "8.8.8.8",
        "GET",
        "/picture.png?token=secret",
    )
    assert headers["Accept"] == "image/png, image/jpeg"
    assert "Cookie" not in headers
    assert "Authorization" not in headers
    assert "Referer" not in headers


def test_redirect_is_revalidated_and_re_resolved():
    responses = [
        _FakeResponse(302, headers={"Location": "https://other.example/image"}, body=b""),
        _FakeResponse(),
    ]
    seen = []
    loader, requests, connections, resolved = _loader(
        responses,
        addresses={"images.example": ("8.8.8.8",), "other.example": ("1.1.1.1",)},
        seen=seen,
    )

    assert loader.fetch("https://images.example/start")[0] == "image/png"
    assert resolved == ["images.example", "other.example"]
    assert connections == [("images.example", "8.8.8.8"), ("other.example", "1.1.1.1")]
    assert len(requests) == 2


def test_rejects_private_urls_credentials_insecure_scheme_and_nonstandard_ports():
    loader, _requests, _connections, _resolved = _loader([])
    urls = (
        "http://images.example/p.png",
        "https://user:pass@images.example/p.png",
        "https://localhost/p.png",
        "https://127.0.0.1/p.png",
        "https://[::1]/p.png",
        "https://images.example:8443/p.png",
    )
    for url in urls:
        with pytest.raises(RemoteImageError):
            loader.fetch(url)


def test_rejects_mixed_public_and_private_dns_answers_and_redirect_to_private_ip():
    loader, _requests, _connections, _resolved = _loader(
        [_FakeResponse()],
        addresses={"images.example": ("8.8.8.8", "10.0.0.1")},
    )
    with pytest.raises(RemoteImageError, match="non-public"):
        loader.fetch("https://images.example/p.png")

    responses = [_FakeResponse(302, headers={"Location": "https://127.0.0.1/private"}, body=b"")]
    loader, _requests, connections, _resolved = _loader(responses)
    with pytest.raises(RemoteImageError, match="non-public"):
        loader.fetch("https://images.example/p.png")
    assert connections == [("images.example", "8.8.8.8")]


def test_rejects_non_image_responses_and_bodies_over_the_byte_cap():
    loader, _requests, _connections, _resolved = _loader(
        [_FakeResponse(headers={"Content-Type": "text/html"}, body=b"<html>fake</html>")]
    )
    with pytest.raises(RemoteImageError, match="supported image"):
        loader.fetch("https://images.example/p.png")

    loader, _requests, _connections, _resolved = _loader([_FakeResponse(body=b"x" * 101)], max_image_bytes=100)
    with pytest.raises(RemoteImageError, match="byte limit"):
        loader.fetch("https://images.example/p.png")


def test_redirect_count_and_per_image_failure_are_bounded():
    responses = [
        _FakeResponse(302, headers={"Location": "https://images.example/next"}, body=b""),
        _FakeResponse(302, headers={"Location": "https://images.example/again"}, body=b""),
        _FakeResponse(302, headers={"Location": "https://images.example/last"}, body=b""),
        _FakeResponse(302, headers={"Location": "https://images.example/overflow"}, body=b""),
    ]
    loader, requests, _connections, _resolved = _loader(responses)
    loader.max_redirects = 2
    with pytest.raises(RemoteImageError, match="redirect limit"):
        loader.fetch("https://images.example/start")
    assert len(requests) == 3

    refs = tuple(RemoteImageRef(index, f"https://images.example/{index}", "images.example") for index in range(1, 5))
    responses = [_FakeResponse(500), _FakeResponse(), _FakeResponse()]
    loader, requests, _connections, _resolved = _loader(responses, max_images=2)
    fetched, skipped = loader.fetch_all(refs)
    assert len(fetched) == 1
    assert [image.index for image in fetched] == [2]
    assert len(skipped) == 3
    assert len(requests) == 2
    assert all("https://" not in repr(item) for item in skipped)
