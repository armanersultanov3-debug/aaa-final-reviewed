"""Active TLS version probing and TLS runtime signal collection.

For each TLS/SSL protocol version the Python ``ssl`` module can express,
attempts a constrained handshake against the target to determine whether
the server supports that version.  The result is a tuple of human-readable
protocol labels (e.g. ``("TLSv1.2", "TLSv1.3")``) suitable for storing
in :pyattr:`TLSInfo.supported_protocols`.

:func:`probe_server_cipher_preference` performs a bounded TLS 1.2 cipher-order
check, while :func:`probe_ocsp_stapling` observes whether the server staples an
OCSP response during the handshake.

:func:`probe_chain_depth` uses ``pyOpenSSL`` (``OpenSSL.SSL``) to retrieve
the full intermediate-certificate chain supplied by the server, which the
Python ``ssl`` stdlib does not expose.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import socket
import ssl
import sys
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from OpenSSL import SSL as _OSSL

_logger = logging.getLogger(__name__)

# Own timeout constant — avoids coupling to recon.py and circular-import
# fragility.  Kept in sync with recon.DEFAULT_TIMEOUT_SECONDS by convention.
DEFAULT_PROBE_TIMEOUT_SECONDS: float = 2.0
_CIPHER_PREFERENCE_ORDER_A = "ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256"
_CIPHER_PREFERENCE_ORDER_B = "AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
_CIPHER_PREFERENCE_INDETERMINATE = (
    "TLS 1.2 cipher preference probe was indeterminate."
)

# --- Protocol definitions ---------------------------------------------------

# Each entry maps a human-readable label to the ``ssl`` module attributes
# needed to constrain a context to *only* that version.
#
# Python >= 3.10 deprecated the per-version ``PROTOCOL_TLSv1`` etc. constants
# in favour of ``TLSVersion`` min/max pinning on a ``TLS_CLIENT`` context.
# We use the modern approach exclusively.

_TLS_VERSIONS: tuple[tuple[str, ssl.TLSVersion, ssl.TLSVersion], ...] = (
    ("TLSv1", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
)


@dataclass(frozen=True, slots=True)
class TLSVersionProbeResult:
    """Outcome of probing a single TLS version against one host:port."""

    label: str
    supported: bool
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class SCTObservation:
    """Serializable view of a Signed Certificate Timestamp."""

    version: str | None = None
    log_id: str | None = None
    timestamp: str | None = None
    entry_type: str | None = None
    signature_hash_algorithm: str | None = None
    signature_algorithm: str | None = None


@dataclass(frozen=True, slots=True)
class TLSCertificateObservation:
    """Observed signature metadata for one certificate in the peer chain."""

    subject: str | None = None
    issuer: str | None = None
    signature_oid: str | None = None
    signature_name: str | None = None
    self_signed: bool = False


@dataclass(frozen=True, slots=True)
class TLSHandshakeObservation:
    """Signals observed directly from the negotiated ServerHello."""

    renegotiation_info_observed: bool | None = None
    negotiated_compression: str | None = None
    negotiated_cipher_is_aead: bool | None = None


_SSL_CTRL_GET_RI_SUPPORT = 76


def observe_tls_handshake_features(
    connection: _OSSL.Connection,
) -> TLSHandshakeObservation:
    """Return ServerHello-era observations from the live OpenSSL connection."""
    ssl_handle = _ssl_handle(connection)
    if ssl_handle is None:
        return TLSHandshakeObservation()

    return TLSHandshakeObservation(
        renegotiation_info_observed=_secure_renegotiation_supported(ssl_handle),
        negotiated_compression=_negotiated_compression_name(ssl_handle),
        negotiated_cipher_is_aead=_negotiated_cipher_is_aead(ssl_handle),
    )


def _ssl_handle(connection: _OSSL.Connection) -> ctypes.c_void_p | None:
    # pyOpenSSL does not expose the raw SSL* via a supported public API. Treat
    # these internals as an optional best-effort compatibility path and degrade
    # to "unobserved" rather than failing the probe when they are unavailable.
    ffi = getattr(_OSSL, "_ffi", None)
    ssl_ptr = getattr(connection, "_ssl", None)
    if ffi is None or ssl_ptr is None:
        return None

    try:
        pointer = int(ffi.cast("uintptr_t", ssl_ptr))
    except (AttributeError, TypeError, ValueError):
        return None
    if pointer == 0:
        return None
    return ctypes.c_void_p(pointer)


def _secure_renegotiation_supported(
    ssl_handle: ctypes.c_void_p,
) -> bool | None:
    libssl = _load_libssl()
    if libssl is None:
        return None
    try:
        # OpenSSL implements SSL_get_secure_renegotiation_support() as the
        # SSL_ctrl(..., SSL_CTRL_GET_RI_SUPPORT, ...) macro.
        return bool(
            libssl.SSL_ctrl(
                ssl_handle,
                _SSL_CTRL_GET_RI_SUPPORT,
                0,
                None,
            )
        )
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _negotiated_compression_name(
    ssl_handle: ctypes.c_void_p,
) -> str | None:
    libssl = _load_libssl()
    if libssl is None:
        return None
    try:
        compression = libssl.SSL_get_current_compression(ssl_handle)
        if not compression:
            return None
        compression_name = libssl.SSL_COMP_get_name(compression)
        if not compression_name:
            return None
    except (AttributeError, OSError, TypeError, ValueError):
        return None

    normalized = compression_name.decode("ascii", errors="ignore").strip().lower()
    if normalized in {"", "null", "none"}:
        return None
    return normalized


def _negotiated_cipher_is_aead(
    ssl_handle: ctypes.c_void_p,
) -> bool | None:
    libssl = _load_libssl()
    if libssl is None:
        return None
    try:
        cipher = libssl.SSL_get_current_cipher(ssl_handle)
        if not cipher:
            return None
        return bool(libssl.SSL_CIPHER_is_aead(cipher))
    except (AttributeError, OSError, TypeError, ValueError):
        return None


@lru_cache(maxsize=1)
def _load_libssl() -> ctypes.CDLL | None:
    for candidate in _candidate_libssl_paths():
        try:
            libssl = ctypes.CDLL(candidate)
        except OSError:
            continue

        if not _configure_libssl_symbol(
            libssl,
            "SSL_ctrl",
            [
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.c_long,
                ctypes.c_void_p,
            ],
            ctypes.c_long,
        ):
            continue

        _configure_libssl_symbol(
            libssl,
            "SSL_get_current_compression",
            [ctypes.c_void_p],
            ctypes.c_void_p,
        )
        _configure_libssl_symbol(
            libssl,
            "SSL_COMP_get_name",
            [ctypes.c_void_p],
            ctypes.c_char_p,
        )
        _configure_libssl_symbol(
            libssl,
            "SSL_get_current_cipher",
            [ctypes.c_void_p],
            ctypes.c_void_p,
        )
        _configure_libssl_symbol(
            libssl,
            "SSL_CIPHER_is_aead",
            [ctypes.c_void_p],
            ctypes.c_int,
        )
        return libssl

    return None


def _configure_libssl_symbol(
    libssl: ctypes.CDLL,
    name: str,
    argtypes: list[object],
    restype: object,
) -> bool:
    try:
        symbol = getattr(libssl, name)
    except AttributeError:
        return False

    symbol.argtypes = argtypes
    symbol.restype = restype
    return True


def _candidate_libssl_paths() -> tuple[str, ...]:
    candidates: list[str] = []

    for library_name in (
        ctypes.util.find_library("ssl"),
        ctypes.util.find_library("libssl"),
    ):
        if library_name:
            candidates.append(library_name)

    if sys.platform == "win32":
        for prefix in (sys.base_exec_prefix, sys.exec_prefix):
            dll_path = Path(prefix) / "DLLs" / "libssl-3.dll"
            candidates.append(str(dll_path))
    else:
        candidates.extend(
            (
                "libssl.so.3",
                "libssl.so",
                "libssl.3.dylib",
                "libssl.dylib",
            )
        )

    return tuple(dict.fromkeys(candidates))


# --- Probing ----------------------------------------------------------------


def _build_tls_context(
    min_ver: ssl.TLSVersion,
    max_ver: ssl.TLSVersion,
) -> ssl.SSLContext:
    """Create an ``SSLContext`` pinned to a single TLS version.

    Certificate verification is disabled because we are interested only in
    whether the handshake succeeds at the protocol level, not whether the
    certificate is trusted.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Python 3.14 warns when pinning deprecated legacy protocol versions
    # (TLSv1/TLSv1.1). We still intentionally probe them to detect insecure
    # server support, so suppress only this narrow warning at assignment time.
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            category=DeprecationWarning,
            message=r"ssl\.TLSVersion\.TLSv1(?:_1)? is deprecated",
        )
        ctx.minimum_version = min_ver
        ctx.maximum_version = max_ver
    return ctx


def _probe_single_version(
    host: str,
    port: int,
    label: str,
    min_ver: ssl.TLSVersion,
    max_ver: ssl.TLSVersion,
    timeout: float,
) -> TLSVersionProbeResult:
    """Try a TLS handshake constrained to one protocol version."""
    try:
        ctx = _build_tls_context(min_ver, max_ver)
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as _tls_sock:
                return TLSVersionProbeResult(label=label, supported=True)
    except (OSError, ssl.SSLError) as exc:
        return TLSVersionProbeResult(
            label=label, supported=False, error_message=str(exc),
        )


def probe_tls_versions(
    host: str,
    port: int,
    timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> list[TLSVersionProbeResult]:
    """Probe *host*:*port* for each known TLS version.

    Returns a list of :class:`TLSVersionProbeResult` in ascending version
    order (TLSv1 … TLSv1.3).  Each entry states whether that version is
    supported.
    """
    results: list[TLSVersionProbeResult] = []
    for label, min_ver, max_ver in _TLS_VERSIONS:
        results.append(
            _probe_single_version(host, port, label, min_ver, max_ver, timeout)
        )
    return results


def supported_protocol_labels(
    results: list[TLSVersionProbeResult],
) -> tuple[str, ...]:
    """Extract the labels of supported versions from probe results."""
    return tuple(r.label for r in results if r.supported)


def describe_signature_algorithm(signature_oid: str | None, signature_name: str | None) -> str:
    """Render one signature algorithm in a stable human-readable form."""
    if signature_name and signature_oid:
        return f"{signature_name} ({signature_oid})"
    if signature_name:
        return signature_name
    if signature_oid:
        return signature_oid
    return "unknown"


def signature_algorithm_is_weak(
    signature_oid: str | None,
    signature_name: str | None,
) -> bool:
    """Return True when a signature algorithm uses MD5 or SHA-1."""
    combined = " ".join(
        part.lower()
        for part in (signature_oid, signature_name)
        if part
    )
    if not combined:
        return False
    return any(marker in combined for marker in ("md5", "sha1", "sha-1"))


def parse_sct_list(serialized_list: bytes) -> tuple[SCTObservation, ...]:
    """Parse RFC 6962 SignedCertificateTimestampList bytes."""
    if len(serialized_list) < 2:
        return ()

    total_length = int.from_bytes(serialized_list[:2], "big")
    if len(serialized_list) != 2 + total_length:
        return ()
    payload = serialized_list[2:]

    scts: list[SCTObservation] = []
    cursor = 0
    while cursor + 2 <= len(payload):
        item_length = int.from_bytes(payload[cursor:cursor + 2], "big")
        cursor += 2
        item = payload[cursor:cursor + item_length]
        cursor += item_length
        if len(item) != item_length:
            return ()
        parsed = _parse_single_sct(item)
        if parsed is None:
            return ()
        scts.append(parsed)

    if cursor != len(payload):
        return ()
    return tuple(scts)


def _parse_single_sct(serialized_sct: bytes) -> SCTObservation | None:
    if len(serialized_sct) < 43:
        return None

    version = serialized_sct[0]
    log_id = serialized_sct[1:33]
    timestamp_ms = int.from_bytes(serialized_sct[33:41], "big")
    extensions_length = int.from_bytes(serialized_sct[41:43], "big")

    cursor = 43 + extensions_length
    if cursor + 4 > len(serialized_sct):
        return None

    hash_algorithm = serialized_sct[cursor]
    signature_algorithm = serialized_sct[cursor + 1]
    signature_length = int.from_bytes(serialized_sct[cursor + 2:cursor + 4], "big")
    cursor += 4
    if cursor + signature_length != len(serialized_sct):
        return None

    try:
        timestamp_text = datetime.fromtimestamp(
            timestamp_ms / 1000,
            tz=timezone.utc,
        ).isoformat()
    except (OverflowError, OSError, ValueError):
        return None

    return SCTObservation(
        version=_sct_version_name(version),
        log_id=log_id.hex(),
        timestamp=timestamp_text,
        entry_type="x509_certificate",
        signature_hash_algorithm=_sct_hash_algorithm_name(hash_algorithm),
        signature_algorithm=_sct_signature_algorithm_name(signature_algorithm),
    )


def _sct_version_name(value: int) -> str:
    if value == 0:
        return "v1"
    return f"unknown({value})"


def _sct_hash_algorithm_name(value: int) -> str:
    return {
        0: "none",
        1: "md5",
        2: "sha1",
        3: "sha224",
        4: "sha256",
        5: "sha384",
        6: "sha512",
    }.get(value, f"unknown({value})")


def _sct_signature_algorithm_name(value: int) -> str:
    return {
        0: "anonymous",
        1: "rsa",
        2: "dsa",
        3: "ecdsa",
    }.get(value, f"unknown({value})")


# --- Cipher preference ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CipherPreferenceProbeResult:
    """Outcome of a bounded TLS 1.2 server cipher-preference probe.

    ``server_order`` is *True* when two handshakes with opposite client
    cipher order select the same suite, *False* when the selected suite
    follows the client order, and *None* when either handshake could not
    produce a comparable cipher.
    """

    server_order: bool | None
    first_cipher: str | None = None
    reversed_cipher: str | None = None
    error_message: str | None = None


def _build_tls12_cipher_context(ciphers: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(ciphers)
    return ctx


def _probe_tls12_cipher(
    host: str,
    port: int,
    ciphers: str,
    timeout: float,
) -> str | None:
    try:
        ctx = _build_tls12_cipher_context(ciphers)
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cipher_tuple = tls_sock.cipher()
    except (OSError, ssl.SSLError, ValueError):
        return None

    if cipher_tuple is None:
        return None
    return cipher_tuple[0]


def probe_server_cipher_preference(
    host: str,
    port: int,
    timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> CipherPreferenceProbeResult:
    """Infer whether a TLS 1.2 endpoint prefers server-side cipher order.

    This deliberately uses only two fixed safe handshakes. It is not a
    full cipher-suite inventory and returns indeterminate when either
    suite pair is unsupported.
    """
    first_cipher = _probe_tls12_cipher(
        host,
        port,
        _CIPHER_PREFERENCE_ORDER_A,
        timeout,
    )
    reversed_cipher = _probe_tls12_cipher(
        host,
        port,
        _CIPHER_PREFERENCE_ORDER_B,
        timeout,
    )

    if first_cipher is None or reversed_cipher is None:
        return CipherPreferenceProbeResult(
            server_order=None,
            first_cipher=first_cipher,
            reversed_cipher=reversed_cipher,
            error_message=_CIPHER_PREFERENCE_INDETERMINATE,
        )

    if first_cipher == reversed_cipher:
        cipher_a, cipher_b = _CIPHER_PREFERENCE_ORDER_A.split(":")
        cipher_a_result = _probe_tls12_cipher(host, port, cipher_a, timeout)
        cipher_b_result = _probe_tls12_cipher(host, port, cipher_b, timeout)
        if cipher_a_result != cipher_a or cipher_b_result != cipher_b:
            return CipherPreferenceProbeResult(
                server_order=None,
                first_cipher=first_cipher,
                reversed_cipher=reversed_cipher,
                error_message=_CIPHER_PREFERENCE_INDETERMINATE,
            )

    return CipherPreferenceProbeResult(
        server_order=first_cipher == reversed_cipher,
        first_cipher=first_cipher,
        reversed_cipher=reversed_cipher,
    )


# --- OCSP stapling ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OCSPStaplingProbeResult:
    """Outcome of requesting an OCSP stapled response during TLS handshake."""

    stapled: bool | None
    error_message: str | None = None


def probe_ocsp_stapling(
    host: str,
    port: int,
    timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> OCSPStaplingProbeResult:
    """Request OCSP stapling support and report whether a response was stapled.

    The check is intentionally passive after a single TLS handshake. It
    does not contact OCSP responders or validate OCSP response freshness.
    """
    if not hasattr(_OSSL.Connection, "request_ocsp"):
        return OCSPStaplingProbeResult(
            stapled=None,
            error_message="OCSP client request support is unavailable.",
        )

    raw_sock: socket.socket | None = None
    conn: _OSSL.Connection | None = None
    ocsp_response: dict[str, bytes | None] = {"value": None}

    def _capture_ocsp_response(_conn, response, _data) -> bool:
        ocsp_response["value"] = response
        return True

    try:
        ctx = _OSSL.Context(_OSSL.TLS_METHOD)
        ctx.set_verify(_OSSL.VERIFY_NONE, lambda *_: True)
        ctx.set_ocsp_client_callback(_capture_ocsp_response)

        raw_sock = socket.create_connection((host, port), timeout=timeout)
        conn = _OSSL.Connection(ctx, raw_sock)
        conn.set_tlsext_host_name(host.encode("idna"))
        conn.request_ocsp()
        conn.set_connect_state()
        conn.do_handshake()

        return OCSPStaplingProbeResult(stapled=ocsp_response["value"] is not None)
    except (OSError, _OSSL.Error, Exception) as exc:  # noqa: BLE001
        return OCSPStaplingProbeResult(stapled=None, error_message=str(exc))
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                _logger.debug("Failed to close OCSP probe connection.", exc_info=True)
        if raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:  # noqa: BLE001
                _logger.debug("Failed to close OCSP probe raw socket.", exc_info=True)


# --- Certificate chain verification ----------------------------------------


@dataclass(frozen=True, slots=True)
class ChainVerificationResult:
    """Outcome of verifying the certificate chain against the system CA store.

    ``verified`` is *True* when the chain is complete and trusted, *False*
    when the chain is definitively broken (e.g. self-signed, missing
    intermediate), and *None* when the check was indeterminate (network
    error, non-verification TLS failure).
    """

    verified: bool | None
    error_message: str | None = None


# OpenSSL verify error codes that represent leaf-certificate validity
# problems rather than trust-chain / intermediate-certificate issues.
# When the *only* failure is one of these, the chain itself is fine.
_LEAF_VALIDITY_VERIFY_CODES: frozenset[int] = frozenset({
    10,  # X509_V_ERR_CERT_HAS_EXPIRED
    9,   # X509_V_ERR_CERT_NOT_YET_VALID
    # Hostname mismatch should not happen (check_hostname=False) but
    # guard against it anyway.
    62,  # X509_V_ERR_HOSTNAME_MISMATCH
})


def verify_certificate_chain(
    host: str,
    port: int,
    timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> ChainVerificationResult:
    """Verify the certificate trust chain against the system CA store.

    Uses :func:`ssl.create_default_context` to load the system CA bundle,
    but **disables hostname checking** so that a hostname / SAN mismatch
    does not cause a false ``cert_chain_incomplete`` finding.

    Leaf-certificate validity problems (expired, not-yet-valid) are
    treated as **indeterminate** for chain-completeness purposes — the
    chain itself may be perfectly fine even though the leaf cert has an
    independent validity issue.  Only trust-chain failures (self-signed,
    missing intermediates, untrusted root) yield ``verified=False``.

    Generic network or TLS errors also yield ``verified=None``.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # hostname mismatch is NOT a chain issue
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as _tls_sock:
                return ChainVerificationResult(verified=True)
    except ssl.SSLCertVerificationError as exc:
        # Distinguish chain failures from leaf-validity failures.
        verify_code = getattr(exc, "verify_code", None)
        if verify_code is not None and verify_code in _LEAF_VALIDITY_VERIFY_CODES:
            # Leaf issue (expired, not-yet-valid) — not a chain problem.
            return ChainVerificationResult(verified=None)
        return ChainVerificationResult(verified=False, error_message=str(exc))
    except (OSError, ssl.SSLError):
        # Network or non-verification TLS errors — we cannot determine
        # chain status; return None to signal indeterminate.
        return ChainVerificationResult(verified=None)


# --- Certificate chain depth ------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChainDepthResult:
    """Outcome of measuring the certificate chain depth via pyOpenSSL.

    ``depth`` is the number of certificates the server sent during the
    handshake (leaf + all intermediates it supplied).  A value of ``1``
    means only the leaf was presented (no intermediates); a value of
    ``None`` means the measurement could not be taken (network error,
    TLS error, unexpected exception).
    """

    depth: int | None
    error_message: str | None = None


def probe_chain_depth(
    host: str,
    port: int,
    timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> ChainDepthResult:
    """Return the number of certificates the server supplied in the handshake.

    Uses ``pyOpenSSL`` (``OpenSSL.SSL``) which exposes
    :meth:`Connection.get_peer_cert_chain` — the Python ``ssl`` stdlib
    does not provide this information.

    Certificate verification is disabled so that expired / self-signed
    certificates do not prevent the chain from being retrieved.
    """
    raw_sock: socket.socket | None = None
    conn: _OSSL.Connection | None = None
    try:
        ctx = _OSSL.Context(_OSSL.TLS_METHOD)
        ctx.set_verify(_OSSL.VERIFY_NONE, lambda *_: True)

        raw_sock = socket.create_connection((host, port), timeout=timeout)
        conn = _OSSL.Connection(ctx, raw_sock)
        conn.set_tlsext_host_name(host.encode("idna"))
        conn.set_connect_state()
        conn.do_handshake()

        chain = conn.get_peer_cert_chain()
        if chain is None:
            return ChainDepthResult(depth=None, error_message="get_peer_cert_chain() returned None")
        return ChainDepthResult(depth=len(chain))
    except (OSError, _OSSL.Error, Exception) as exc:  # noqa: BLE001
        return ChainDepthResult(depth=None, error_message=str(exc))
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                _logger.debug("Failed to close pyOpenSSL connection.", exc_info=True)
        if raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:  # noqa: BLE001
                _logger.debug("Failed to close TLS probe raw socket.", exc_info=True)


__all__ = [
    "ChainDepthResult",
    "ChainVerificationResult",
    "CipherPreferenceProbeResult",
    "OCSPStaplingProbeResult",
    "SCTObservation",
    "TLSHandshakeObservation",
    "TLSVersionProbeResult",
    "TLSCertificateObservation",
    "describe_signature_algorithm",
    "observe_tls_handshake_features",
    "parse_sct_list",
    "probe_chain_depth",
    "probe_ocsp_stapling",
    "probe_server_cipher_preference",
    "probe_tls_versions",
    "signature_algorithm_is_weak",
    "supported_protocol_labels",
    "verify_certificate_chain",
]
