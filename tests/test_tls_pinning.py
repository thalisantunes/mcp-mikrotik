"""api-ssl certificate pinning (`tls_fingerprint`), end to end against a
real local TLS server.

Every certificate here is a throwaway self-signed one generated at test
time (CN "test-router", deliberately with NO subjectAltName - the shape of
the RouterOS certificates pinning exists for), and the "router" is a tiny
in-process TLS server on 127.0.0.1 that speaks just enough RouterOS API
framing to answer every sentence with `!done`. It records every byte it
receives after the TLS handshake, which is what lets these tests prove the
central guarantee: on a fingerprint mismatch the connection is closed
before a single RouterOS login byte (let alone the password) is sent.
"""

from __future__ import annotations

import datetime
import shutil
import socket
import ssl
import subprocess
import textwrap
import threading
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from librouteros.protocol import decode_length, determine_length, encode_sentence
from mcp.server.fastmcp.exceptions import ToolError

from mcp_mikrotik.client import (
    MikrotikClient,
    _build_ssl_context,
    _connect,
    _format_fingerprint,
    _verify_peer_fingerprint,
    get_client,
)
from mcp_mikrotik.config import Device, Settings, load_devices, normalize_tls_fingerprint
from mcp_mikrotik.exceptions import CircuitOpenError, DeviceConnectionError, TLSFingerprintMismatchError
from mcp_mikrotik.server import build_server

PASSWORD = "s3cret-pw"


# --- Test certificates --------------------------------------------------------


@dataclass(frozen=True)
class GeneratedCert:
    cert_path: Path
    key_path: Path
    fingerprint: str  # SHA-256 of the DER certificate, 64 lowercase hex chars


def _make_self_signed_cert(directory: Path, label: str) -> GeneratedCert:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-router")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / f"{label}.crt"
    key_path = directory / f"{label}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return GeneratedCert(cert_path, key_path, cert.fingerprint(hashes.SHA256()).hex())


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> tuple[GeneratedCert, GeneratedCert]:
    directory = tmp_path_factory.mktemp("tls-pinning-certs")
    return _make_self_signed_cert(directory, "router-a"), _make_self_signed_cert(directory, "router-b")


@pytest.fixture
def cert_a(certs: tuple[GeneratedCert, GeneratedCert]) -> GeneratedCert:
    return certs[0]


@pytest.fixture
def cert_b(certs: tuple[GeneratedCert, GeneratedCert]) -> GeneratedCert:
    return certs[1]


# --- A minimal local api-ssl endpoint -------------------------------------------


@dataclass
class ConnectionRecord:
    handshake_completed: bool = False
    received_after_handshake: bytes = b""
    peer_closed: bool = False
    done: threading.Event = field(default_factory=threading.Event)


def _complete_sentences(buffer: bytes) -> tuple[int, bytes]:
    """Count complete RouterOS API sentences at the start of `buffer`
    (words are length-prefixed; a zero-length word ends a sentence) and
    return the count plus the unconsumed remainder."""
    count = 0
    consumed = 0
    index = 0
    while index < len(buffer):
        extra = determine_length(buffer[index : index + 1])
        if index + 1 + extra > len(buffer):
            break
        length = decode_length(buffer[index : index + 1 + extra])
        index += 1 + extra
        if length == 0:
            count += 1
            consumed = index
            continue
        if index + length > len(buffer):
            break
        index += length
    return count, buffer[consumed:]


class FakeApiSslServer:
    """Accepts TLS connections on 127.0.0.1 with the given certificate and
    answers every RouterOS API sentence with `!done` - enough for
    librouteros' plain login and for a print to return no rows. One
    ConnectionRecord per accepted connection, in order."""

    DONE = encode_sentence("!done", encoding="ASCII")

    def __init__(self, cert: GeneratedCert, max_tls_version: ssl.TLSVersion | None = None):
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(cert.cert_path, cert.key_path)
        # No TLS 1.3 session tickets: otherwise a client that closes right
        # after its handshake may leave them unread and reset the
        # connection, which would make "what did the server receive" racy.
        self._context.num_tickets = 0
        if max_tls_version is not None:
            self._context.maximum_version = max_tls_version
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.1)
        self.port: int = self._listener.getsockname()[1]
        self.connections: list[ConnectionRecord] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> FakeApiSslServer:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        self._thread.join(timeout=10)
        self._listener.close()

    def wait_for_connection(self, index: int = 0, timeout: float = 10.0) -> ConnectionRecord:
        """Block until connection `index` has been fully handled (peer
        closed, error, or timeout) so its record is final."""
        for _ in range(int(timeout / 0.01)):
            if len(self.connections) > index:
                break
            self._stop.wait(0.01)
        record = self.connections[index]
        assert record.done.wait(timeout), "fake api-ssl server never finished handling the connection"
        return record

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _addr = self._listener.accept()
            except TimeoutError:
                continue
            record = ConnectionRecord()
            self.connections.append(record)
            self._handle(raw, record)

    def _handle(self, raw: socket.socket, record: ConnectionRecord) -> None:
        raw.settimeout(5)
        try:
            tls = self._context.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close()
            record.done.set()
            return
        record.handshake_completed = True
        pending = b""
        try:
            while True:
                try:
                    chunk = tls.recv(4096)
                except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError):
                    chunk = b""
                if not chunk:
                    record.peer_closed = True
                    return
                record.received_after_handshake += chunk
                sentences, pending = _complete_sentences(pending + chunk)
                for _ in range(sentences):
                    tls.sendall(self.DONE)
        except OSError:
            return  # read timeout or other socket error: record stays as-is
        finally:
            tls.close()
            record.done.set()


def _pinned_device(port: int, *pins: str, name: str = "pinned-router") -> Device:
    return Device(
        name=name,
        host="127.0.0.1",
        port=port,
        use_ssl=True,
        username="admin",
        password=PASSWORD,
        tls_fingerprints=tuple(pins),
        timeout=5,
    )


# --- Matching pin: the connection proceeds to login ---------------------------


def test_matching_pin_connects_and_logs_in(cert_a: GeneratedCert):
    with FakeApiSslServer(cert_a) as server:
        client = MikrotikClient(_pinned_device(server.port, cert_a.fingerprint))
        assert client.path("system", "identity") == []
        client.close()
        record = server.wait_for_connection()

    assert record.handshake_completed
    # Login happened on this (pinned) connection: the server saw /login with
    # the credentials, then the print.
    assert b"/login" in record.received_after_handshake
    assert PASSWORD.encode() in record.received_after_handshake
    assert b"/system/identity/print" in record.received_after_handshake
    assert len(server.connections) == 1


def test_pin_from_yaml_in_openssl_format_connects(cert_a: GeneratedCert, tmp_path: Path):
    """The value an operator pastes from `openssl x509 -noout -fingerprint
    -sha256` (upper-case, ':'-separated) with a `sha256:` prefix goes
    through config loading and authenticates the real certificate."""
    with FakeApiSslServer(cert_a) as server:
        devices_file = tmp_path / "devices.yaml"
        devices_file.write_text(
            textwrap.dedent(
                f"""
                devices:
                  - name: pinned-router
                    host: 127.0.0.1
                    port: {server.port}
                    use_ssl: true
                    username: admin
                    password: {PASSWORD}
                    tls_fingerprint: "sha256:{_format_fingerprint(cert_a.fingerprint)}"
                """
            )
        )
        device = load_devices(devices_file)["pinned-router"]
        connection = _connect(device)
        connection.close()
        record = server.wait_for_connection()

    assert record.handshake_completed
    assert b"/login" in record.received_after_handshake


def test_list_of_pins_accepts_any_listed_certificate(cert_a: GeneratedCert, cert_b: GeneratedCert):
    """Rotation: with [old, new] pinned, whichever certificate the device
    currently serves is accepted."""
    for served in (cert_a, cert_b):
        with FakeApiSslServer(served) as server:
            client = MikrotikClient(_pinned_device(server.port, cert_b.fingerprint, cert_a.fingerprint))
            assert client.path("system", "identity") == []
            client.close()
            record = server.wait_for_connection()
        assert b"/login" in record.received_after_handshake


# --- Mismatching pin: refused before any login byte -----------------------------


@pytest.mark.parametrize("max_tls_version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_mismatching_pin_fails_before_any_login_bytes(
    cert_a: GeneratedCert, cert_b: GeneratedCert, max_tls_version: ssl.TLSVersion
):
    with FakeApiSslServer(cert_a, max_tls_version=max_tls_version) as server:
        device = _pinned_device(server.port, cert_b.fingerprint)
        with pytest.raises(TLSFingerprintMismatchError) as exc_info:
            _connect(device)
        record = server.wait_for_connection()

    # The TLS handshake itself completed (the pin is checked on the
    # certificate the handshake delivered) ...
    assert record.handshake_completed
    # ... but the server received NOTHING after it - no /login sentence, no
    # username, no password - and saw the client close the connection.
    assert record.received_after_handshake == b""
    assert record.peer_closed

    message = str(exc_info.value)
    assert PASSWORD not in message
    assert "pinned-router" in message
    assert _format_fingerprint(cert_a.fingerprint) in message  # what the peer presented
    assert _format_fingerprint(cert_b.fingerprint) in message  # what was expected
    assert "no credentials were sent" in message
    assert exc_info.value.presented == _format_fingerprint(cert_a.fingerprint)
    assert exc_info.value.expected == (_format_fingerprint(cert_b.fingerprint),)


def test_mismatch_with_several_pins_lists_all_of_them(cert_a: GeneratedCert, cert_b: GeneratedCert):
    other = "00" * 32
    with FakeApiSslServer(cert_a) as server:
        with pytest.raises(TLSFingerprintMismatchError) as exc_info:
            _connect(_pinned_device(server.port, cert_b.fingerprint, other))
        record = server.wait_for_connection()
    assert record.received_after_handshake == b""
    message = str(exc_info.value)
    assert "expected one of" in message
    assert _format_fingerprint(cert_b.fingerprint) in message
    assert _format_fingerprint(other) in message


def test_peer_without_a_certificate_fails_closed():
    """A peer that presents no certificate at all can never satisfy a pin.

    Unlike the tests above, this is a unit test of _verify_peer_fingerprint
    with a stub socket, not a handshake against FakeApiSslServer: a live
    certificate-less handshake isn't reachable with the pinned context,
    since its cipher list offers no anonymous (aNULL) suite and TLS 1.3 has
    none (see the next test). The no-certificate branch is defence in depth."""

    class NoCertSocket:
        def getpeercert(self, binary_form: bool = False):
            return None

    device = _pinned_device(8729, "ab" * 32)
    with pytest.raises(TLSFingerprintMismatchError) as exc_info:
        _verify_peer_fingerprint(NoCertSocket(), device)
    assert "presented no certificate" in str(exc_info.value)
    assert exc_info.value.presented is None


def test_pinned_context_offers_no_anonymous_cipher_suites():
    """Why the no-certificate branch above is unreachable in a real
    handshake: the context used for a pinned device never offers a suite
    that lets the server skip sending a certificate."""
    context = _build_ssl_context(_pinned_device(8729, "ab" * 32))
    ciphers = context.get_ciphers()
    assert ciphers
    assert [c["name"] for c in ciphers if c.get("auth") == "auth-null"] == []


# --- Error classification: no read retry, counts toward the breaker -----------


def test_mismatch_is_not_retried_and_counts_toward_the_breaker(
    cert_a: GeneratedCert, cert_b: GeneratedCert, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("MIKROTIK_READ_RETRIES", "2")  # a plain connect failure would be tried 3 times
    monkeypatch.setenv("MIKROTIK_BREAKER_THRESHOLD", "2")
    with FakeApiSslServer(cert_a) as server:
        client = MikrotikClient(_pinned_device(server.port, cert_b.fingerprint))

        with pytest.raises(TLSFingerprintMismatchError):
            client.path("system", "identity")
        server.wait_for_connection(0)
        assert len(server.connections) == 1  # exactly one attempt: not retried
        assert client._breaker.is_open is False  # 1 failure, threshold 2

        with pytest.raises(TLSFingerprintMismatchError):
            client.path("system", "identity")
        server.wait_for_connection(1)
        assert len(server.connections) == 2
        assert client._breaker.is_open is True  # counted like any connection failure

        with pytest.raises(CircuitOpenError):
            client.path("system", "identity")
        assert len(server.connections) == 2  # breaker open: no new socket at all

    assert all(record.received_after_handshake == b"" for record in server.connections)


def test_mismatch_is_a_device_connection_error_for_existing_handlers():
    exc = TLSFingerprintMismatchError("d1", "AA", ("BB",))
    assert isinstance(exc, DeviceConnectionError)
    assert not isinstance(exc, CircuitOpenError)


# --- Why pinning: the same certificate fails CA + hostname verification ---------


def test_without_a_pin_ca_verification_rejects_a_certificate_lacking_a_san(cert_a: GeneratedCert):
    """The motivating case: even trusting the device's own certificate as
    the CA, a certificate with no subjectAltName for the address connected
    to cannot pass CA + hostname verification - while the pin above
    authenticates the very same certificate."""
    with FakeApiSslServer(cert_a) as server:
        device = Device(
            name="ca-mode-router",
            host="127.0.0.1",
            port=server.port,
            use_ssl=True,
            password=PASSWORD,
            tls_ca_cert=str(cert_a.cert_path),
            timeout=5,
        )
        with pytest.raises(DeviceConnectionError) as exc_info:
            _connect(device)
        server.wait_for_connection()
    assert not isinstance(exc_info.value, TLSFingerprintMismatchError)
    assert PASSWORD not in str(exc_info.value)


def test_build_ssl_context_with_pins_skips_chain_and_hostname_checks():
    # Even with tls_verify left at its default (True), pins take precedence:
    # the pin is the authentication, enforced right after the handshake.
    device = Device(name="d1", host="192.0.2.1", use_ssl=True, tls_fingerprints=("ab" * 32,))
    assert device.tls_verify is True
    context = _build_ssl_context(device)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def test_connect_uses_the_pinned_wrapper_only_when_pins_are_set(monkeypatch: pytest.MonkeyPatch):
    captured: list[object] = []

    def fake_connect(**kwargs):
        captured.append(kwargs["ssl_wrapper"])
        return object()

    monkeypatch.setattr("mcp_mikrotik.client.librouteros.connect", fake_connect)
    _connect(Device(name="plain-tls", host="192.0.2.1", use_ssl=True, tls_verify=False))
    _connect(Device(name="pinned", host="192.0.2.1", use_ssl=True, tls_fingerprints=("ab" * 32,)))
    unpinned_wrapper, pinned_wrapper = captured
    assert getattr(unpinned_wrapper, "__name__", "") != "wrap"
    assert getattr(pinned_wrapper, "__name__", "") == "wrap"


# --- Through the MCP tool boundary ---------------------------------------------


@pytest.mark.asyncio
async def test_tool_call_against_a_mismatching_device_returns_a_clear_error(
    cert_a: GeneratedCert, cert_b: GeneratedCert
):
    with FakeApiSslServer(cert_a) as server:
        device = _pinned_device(server.port, cert_b.fingerprint)
        mcp = build_server(settings=Settings(allow_write=False, devices={device.name: device}))
        with pytest.raises(ToolError) as exc_info:
            await mcp.call_tool("system_info", {"device_name": device.name})
        server.wait_for_connection()

    message = str(exc_info.value)
    assert "fingerprint mismatch" in message
    assert _format_fingerprint(cert_a.fingerprint) in message
    assert PASSWORD not in message
    assert len(server.connections) == 1
    assert server.connections[0].received_after_handshake == b""


@pytest.mark.asyncio
async def test_tool_call_against_a_matching_device_succeeds_and_list_devices_is_unchanged(cert_a: GeneratedCert):
    created: list[MikrotikClient] = []

    def factory(settings: Settings, name: str) -> MikrotikClient:
        client = get_client(settings, name)
        created.append(client)
        return client

    with FakeApiSslServer(cert_a) as server:
        device = _pinned_device(server.port, cert_a.fingerprint)
        mcp = build_server(settings=Settings(allow_write=False, devices={device.name: device}), client_factory=factory)
        _content, result = await mcp.call_tool("system_info", {"device_name": device.name})
        assert result == {"identity": {}, "resource": {}}

        _content, listed = await mcp.call_tool("list_devices", {})
        # The pin is not secret, but tool output doesn't need it: same keys as
        # for any other device.
        assert set(listed["result"][0]) == {"name", "host", "port", "use_ssl", "username", "disabled", "comment"}

        for client in created:
            client.close()
        record = server.wait_for_connection()

    assert b"/login" in record.received_after_handshake
    assert len(server.connections) == 1  # one pooled, pinned connection served both reads


# --- The documented way to obtain a fingerprint ---------------------------------


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")
def test_documented_openssl_command_yields_an_accepted_fingerprint(cert_a: GeneratedCert):
    """README tells operators to run `openssl x509 -noout -fingerprint
    -sha256 -in <exported.crt>` and paste the value after '='. Prove that
    value is accepted and equals the SHA-256 of the DER certificate the
    server presents."""
    output = subprocess.run(
        ["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", str(cert_a.cert_path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    value = output.strip().split("=", 1)[1]
    assert normalize_tls_fingerprint(value) == cert_a.fingerprint
