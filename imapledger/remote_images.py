from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from collections.abc import Callable, Iterable
from urllib.parse import urljoin, urlsplit

from .image_analysis import MAX_EMBEDDED_IMAGES, MAX_IMAGE_BYTES, ImageSkip
from .message import MailImage, RemoteImageRef

MAX_REDIRECTS = 3
CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 10.0
MAX_URL_CHARS = 2048
_ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg"}


class RemoteImageError(ValueError):
    """A remote image failed the local privacy or response policy."""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, *, connect_timeout: float, read_timeout: float) -> None:
        connection_host = f"[{host}]" if ":" in host else host
        super().__init__(connection_host, 443, timeout=connect_timeout, context=ssl.create_default_context())
        self._tls_hostname = host
        self._address = address
        self._read_timeout = read_timeout

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        sock.settimeout(self._read_timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._tls_hostname)


class RemoteImageLoader:
    def __init__(
        self,
        *,
        max_images: int = MAX_EMBEDDED_IMAGES,
        max_image_bytes: int = MAX_IMAGE_BYTES,
        max_redirects: int = MAX_REDIRECTS,
        connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
        read_timeout: float = READ_TIMEOUT_SECONDS,
        resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
        connection_factory: Callable[..., http.client.HTTPSConnection] | None = None,
    ) -> None:
        if not 0 <= max_images <= MAX_EMBEDDED_IMAGES:
            raise ValueError("remote image count exceeds the shared image limit")
        if not 1 <= max_image_bytes <= MAX_IMAGE_BYTES:
            raise ValueError("remote image byte limit exceeds the shared byte limit")
        if not 0 <= max_redirects <= MAX_REDIRECTS:
            raise ValueError("remote redirect count exceeds the shared redirect limit")
        if not 0 < connect_timeout <= CONNECT_TIMEOUT_SECONDS:
            raise ValueError("remote connect timeout exceeds the shared timeout limit")
        if not 0 < read_timeout <= READ_TIMEOUT_SECONDS:
            raise ValueError("remote read timeout exceeds the shared timeout limit")
        self.max_images = max_images
        self.max_image_bytes = max_image_bytes
        self.max_redirects = max_redirects
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self._resolver = resolver
        self._connection_factory = connection_factory or self._connect

    def _connect(
        self,
        host: str,
        address: str,
        *,
        connect_timeout: float,
        read_timeout: float,
    ) -> http.client.HTTPSConnection:
        return _PinnedHTTPSConnection(
            host,
            address,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )

    def fetch_all(self, refs: Iterable[RemoteImageRef]) -> tuple[tuple[MailImage, ...], tuple[ImageSkip, ...]]:
        images: list[MailImage] = []
        skipped: list[ImageSkip] = []
        for ref in refs:
            if len(images) + len(skipped) >= self.max_images:
                skipped.append(ImageSkip(ref.index, "remote", 0, "remote image limit reached"))
                continue
            try:
                content_type, data = self.fetch(ref.url)
            except Exception:
                skipped.append(
                    ImageSkip(ref.index, "remote", 0, "remote image unavailable or blocked by privacy policy")
                )
                continue
            images.append(
                MailImage(
                    index=ref.index,
                    content_type=content_type,
                    filename="",
                    content_id="",
                    disposition="remote",
                    data=data,
                    size_bytes=len(data),
                    classifiable=True,
                )
            )
        return tuple(images), tuple(skipped)

    def fetch(self, url: str) -> tuple[str, bytes]:
        current_url = url
        for redirect_count in range(self.max_redirects + 1):
            parsed = self._parse_url(current_url)
            host = parsed.hostname
            if host is None:
                raise RemoteImageError("remote URL has no hostname")
            address = self._resolve_public_address(host)
            connection = self._connection_factory(
                host,
                address,
                connect_timeout=self.connect_timeout,
                read_timeout=self.read_timeout,
            )
            target = parsed.path or "/"
            if parsed.query:
                target += f"?{parsed.query}"
            try:
                connection.request(
                    "GET",
                    target,
                    headers={"Accept": "image/png, image/jpeg", "Connection": "close"},
                )
                response = connection.getresponse()
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.getheader("Location")
                    response.read(0)
                    if redirect_count >= self.max_redirects or not location:
                        raise RemoteImageError("remote redirect limit reached")
                    current_url = urljoin(current_url, location)
                    continue
                if response.status != 200:
                    raise RemoteImageError("remote server returned a non-success status")
                content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
                if content_type not in _ALLOWED_CONTENT_TYPES:
                    raise RemoteImageError("remote response is not a supported image")
                content_encoding = (response.getheader("Content-Encoding") or "identity").lower()
                if content_encoding not in {"", "identity"}:
                    raise RemoteImageError("encoded remote responses are not supported")
                content_length = response.getheader("Content-Length")
                if content_length is not None:
                    try:
                        content_length_value = int(content_length)
                    except ValueError as exc:
                        raise RemoteImageError("invalid remote content length") from exc
                    if content_length_value < 0:
                        raise RemoteImageError("invalid remote content length")
                    if content_length_value > self.max_image_bytes:
                        raise RemoteImageError("remote image exceeds byte limit")
                data = response.read(self.max_image_bytes + 1)
                if len(data) > self.max_image_bytes:
                    raise RemoteImageError("remote image exceeds byte limit")
                if not data:
                    raise RemoteImageError("remote image is empty")
                return content_type, data
            finally:
                connection.close()
        raise RemoteImageError("remote redirect limit reached")

    def _parse_url(self, url: str):
        if (
            not isinstance(url, str)
            or len(url) > MAX_URL_CHARS
            or any(ord(char) < 32 or ord(char) == 127 for char in url)
        ):
            raise RemoteImageError("remote URL exceeds policy limits")
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise RemoteImageError("invalid remote URL") from exc
        if parsed.scheme.lower() != "https" or not host or parsed.username is not None or parsed.password is not None:
            raise RemoteImageError("only credential-free HTTPS image URLs are allowed")
        if port not in (None, 443) or "%" in host:
            raise RemoteImageError("remote URL uses a disallowed host or port")
        try:
            normalized_host = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise RemoteImageError("invalid remote hostname") from exc
        if not normalized_host:
            raise RemoteImageError("remote URL has no hostname")
        if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
            raise RemoteImageError("local hostnames are not allowed")
        netloc = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
        return parsed._replace(netloc=netloc)

    def _resolve_public_address(self, host: str) -> str:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if not literal.is_global:
                raise RemoteImageError("non-public IP addresses are not allowed")
            return str(literal)
        try:
            results = self._resolver(host, 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise RemoteImageError("remote hostname could not be resolved") from exc
        addresses = {result[4][0] for result in results}
        if not addresses:
            raise RemoteImageError("remote hostname did not resolve")
        for address in addresses:
            try:
                parsed_address = ipaddress.ip_address(address)
            except ValueError as exc:
                raise RemoteImageError("remote hostname returned an invalid address") from exc
            if not parsed_address.is_global:
                raise RemoteImageError("remote hostname resolves to a non-public address")
        return next(iter(addresses))
