"""Reading a TLS certificate with nothing but the standard library.

`ssl` will perform the handshake and hand back the certificate as DER, but it will
not decode it. A scanner that had to `pip install cryptography` before it could
tell you a certificate expired is a scanner that does not run on the client's jump
host. So this is the same small DER reader that lives in `tlsradar`, trimmed to
what a finding needs: the validity window, the subject and the issuer.
"""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Optional, Tuple


class CertError(ValueError):
    """The bytes were not a certificate we could read."""


def _tlv(buf: bytes, i: int) -> Tuple[int, int, int]:
    if i + 2 > len(buf):
        raise CertError("truncated tag/length")
    tag, length_byte = buf[i], buf[i + 1]
    i += 2
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0 or count > 4 or i + count > len(buf):
            raise CertError("unsupported length")
        length = int.from_bytes(buf[i:i + count], "big")
        i += count
    else:
        length = length_byte
    end = i + length
    if end > len(buf):
        raise CertError("truncated value")
    return tag, i, end


def _children(buf: bytes, start: int, end: int):
    out = []
    i = start
    while i < end:
        tag, cs, ce = _tlv(buf, i)
        out.append((tag, cs, ce))
        i = ce
    return out


def _time(raw: bytes) -> datetime.datetime:
    text = raw.decode("ascii", "replace").strip().rstrip("Zz")
    if len(text) == 12:                                    # UTCTime
        year = int(text[:2])
        text = f"{year + (2000 if year < 50 else 1900):04d}" + text[2:]
    if len(text) != 14 or not text.isdigit():
        raise CertError(f"unsupported time format: {raw!r}")
    return datetime.datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=datetime.timezone.utc)


def parse_validity(der: bytes) -> Tuple[datetime.datetime, datetime.datetime]:
    """(notBefore, notAfter) from a DER certificate."""
    tag, cs, ce = _tlv(der, 0)
    if tag != 0x30:
        raise CertError("certificate is not a SEQUENCE")
    outer = _children(der, cs, ce)
    if not outer or outer[0][0] != 0x30:
        raise CertError("no tbsCertificate")
    _, tbs_start, tbs_end = outer[0]
    sequences = [item for item in _children(der, tbs_start, tbs_end) if item[0] == 0x30]
    if len(sequences) < 4:
        raise CertError("certificate is missing issuer/validity/subject")
    validity = _children(der, sequences[2][1], sequences[2][2])
    if len(validity) < 2:
        raise CertError("validity has no notBefore/notAfter pair")
    return _time(der[validity[0][1]:validity[0][2]]), _time(der[validity[1][1]:validity[1][2]])


def parse_subject(der: bytes) -> str:
    """The subject as 'CN=x, O=y, C=z' — enough for a report."""
    label = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
             "2.5.4.10": "O", "2.5.4.11": "OU"}
    tag, cs, ce = _tlv(der, 0)
    outer = _children(der, cs, ce)
    if not outer or outer[0][0] != 0x30:
        raise CertError("no tbsCertificate")
    _, tbs_start, tbs_end = outer[0]
    sequences = [item for item in _children(der, tbs_start, tbs_end) if item[0] == 0x30]
    if len(sequences) < 4:
        raise CertError("certificate is missing subject")
    found = {}
    for set_tag, set_start, set_end in _children(der, sequences[3][1], sequences[3][2]):
        if set_tag != 0x31:
            continue
        for seq_tag, seq_start, seq_end in _children(der, set_start, set_end):
            if seq_tag != 0x30:
                continue
            parts = _children(der, seq_start, seq_end)
            if len(parts) != 2:
                continue
            raw_oid = der[parts[0][1]:parts[0][2]]
            if not raw_oid:
                continue
            dotted = [str(raw_oid[0] // 40), str(raw_oid[0] % 40)]
            value = 0
            for byte in raw_oid[1:]:
                value = (value << 7) | (byte & 0x7F)
                if not byte & 0x80:
                    dotted.append(str(value))
                    value = 0
            key = label.get(".".join(dotted))
            if key:
                found.setdefault(key, der[parts[1][1]:parts[1][2]].decode("utf-8", "replace"))
    return ", ".join(f"{key}={found[key]}" for key in ("CN", "O", "OU", "L", "ST", "C") if key in found)


class PeerCertificate:
    """What a handshake told us."""

    def __init__(self, not_before=None, not_after=None, subject="", verified=False,
                 tls_version="", cipher="", error=""):
        self.not_before = not_before
        self.not_after = not_after
        self.subject = subject
        self.verified = verified
        self.tls_version = tls_version
        self.cipher = cipher
        self.error = error

    @property
    def days_left(self) -> Optional[int]:
        if self.not_after is None:
            return None
        delta = self.not_after - datetime.datetime.now(datetime.timezone.utc)
        return int(delta.total_seconds() // 86400)

    @property
    def weak_protocol(self) -> bool:
        return self.tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")


def fetch(host: str, port: int, timeout: float = 8.0, sni: Optional[str] = None) -> PeerCertificate:
    """Handshake twice: verified first, then unverified so a bad cert is still read."""
    server_name = sni or host

    def handshake(context: ssl.SSLContext, check: bool) -> PeerCertificate:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as tls:
                der = tls.getpeercert(binary_form=True) or b""
                certificate = PeerCertificate(verified=check, tls_version=tls.version() or "",
                                              cipher=tls.cipher()[0] if tls.cipher() else "")
                try:
                    certificate.not_before, certificate.not_after = parse_validity(der)
                    certificate.subject = parse_subject(der)
                except CertError as exc:
                    certificate.error = f"could not read the certificate: {exc}"
                return certificate

    try:
        return handshake(ssl.create_default_context(), True)
    except ssl.SSLCertVerificationError as exc:
        reason = exc.verify_message or str(exc)
    except ssl.SSLError as exc:
        raise CertError(f"TLS handshake failed: {exc}") from exc
    except OSError as exc:
        # Anything that is not TLS: the service closed the connection mid-handshake, or
        # there is nothing listening after all. Windows raises ConnectionAbortedError
        # (WinError 10053) where Linux raises a reset or a clean EOF, so this has to be
        # caught here rather than left to the caller: an unhandled OSError in the middle
        # of a check is a scan that dies on one port.
        raise CertError(f"no TLS handshake could be completed: {exc}") from exc

    lax = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    lax.check_hostname = False
    lax.verify_mode = ssl.CERT_NONE
    try:
        certificate = handshake(lax, False)
    except (ssl.SSLError, OSError, ValueError) as exc:
        # ValueError: an empty server hostname, which a caller can produce by scanning
        # a bare address over a proxy. Either way, it is a certificate we could not read.
        raise CertError(f"{reason} (and the retry failed: {exc})") from exc
    certificate.error = reason
    return certificate
