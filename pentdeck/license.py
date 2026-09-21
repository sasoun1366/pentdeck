"""Offline licences: a signed token that unlocks the paid half of the tool.

The token is `PD1.<base64url(payload)>.<base64url(hmac-sha256)>` — verifiable with
nothing but the standard library, which is the whole point: a customer installs an
exe, pastes a token, and the app works with no network and no licence server.

Being honest about what this is worth: anyone determined can patch a check out of
a Python program, and a shared secret that ships inside the app can be extracted.
This is a lock that keeps honest customers honest and makes paying the easy path —
not DRM, and it is not sold as DRM.

Tiers:
    free  what the tool does without a licence
    pro   one operator, everything unlocked
    team  several operators, everything unlocked
"""

from __future__ import annotations

import base64
import dataclasses
import datetime
import hashlib
import hmac
import json
import os
import pathlib
import platform
import secrets
import sys
import uuid
from typing import Any, Dict, List, Optional, Sequence

TOKEN_PREFIX = "PD1"
LICENSE_FILENAME = "license.json"
MACHINE_FILENAME = "machine.json"

#: Read by the app at start-up. Keep the real value in the build, not in git:
#: `export PENTDECK_LICENSE_SECRET=...` before packaging, or drop it into
#: ~/.pentdeck/secret (mode 0600) on the machine that issues licences.
SECRET_ENV = "PENTDECK_LICENSE_SECRET"

TIERS: Dict[str, Dict[str, Any]] = {
    "free": {
        "label": "Free",
        "price_usd": 0,
        "max_hosts": 16,
        "checks": ["ports", "banner"],
        "reports": ["text"],
        "intrusive": False,
        "operators": 1,
        "support": False,
    },
    "pro": {
        "label": "Pro",
        "price_usd": 99,
        "max_hosts": 0,                 # 0 = no limit
        "checks": ["ports", "banner", "tls", "http", "plaintext", "dns-zone-transfer"],
        "reports": ["text", "json", "markdown", "html"],
        "intrusive": True,
        "operators": 1,
        "support": True,
    },
    "team": {
        "label": "Team",
        "price_usd": 299,
        "max_hosts": 0,
        "checks": ["ports", "banner", "tls", "http", "plaintext", "dns-zone-transfer"],
        "reports": ["text", "json", "markdown", "html"],
        "intrusive": True,
        "operators": 25,
        "support": True,
    },
}

REPORT_EXTENSIONS = {"text": "txt", "json": "json", "markdown": "md", "html": "html"}


class LicenseError(ValueError):
    """A licence problem the user can act on."""


@dataclasses.dataclass
class License:
    """A verified licence."""

    customer: str = ""
    tier: str = "free"
    order: str = ""
    issued: str = ""
    expires: Optional[str] = None
    machine: str = ""
    seats: int = 1
    token: str = ""

    # ── what the tier allows ─────────────────────────────────────────────────
    @property
    def limits(self) -> Dict[str, Any]:
        return TIERS.get(self.tier, TIERS["free"])

    @property
    def is_paid(self) -> bool:
        return self.tier in ("pro", "team") and not self.is_expired

    @property
    def is_expired(self) -> bool:
        if not self.expires:
            return False
        try:
            moment = datetime.datetime.fromisoformat(self.expires)
        except ValueError:
            return True
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=datetime.timezone.utc)
        return moment < datetime.datetime.now(datetime.timezone.utc)

    @property
    def days_left(self) -> Optional[int]:
        if not self.expires:
            return None
        moment = datetime.datetime.fromisoformat(self.expires)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=datetime.timezone.utc)
        return int((moment - datetime.datetime.now(datetime.timezone.utc)).total_seconds() // 86400)

    def allows_check(self, name: str) -> bool:
        if self.is_expired:
            return name in TIERS["free"]["checks"]
        return name in self.limits["checks"]

    def allows_report(self, kind: str) -> bool:
        if self.is_expired:
            return kind in TIERS["free"]["reports"]
        return kind in self.limits["reports"]

    def allows_intrusive(self) -> bool:
        return bool(self.limits["intrusive"]) and not self.is_expired

    def host_limit(self) -> int:
        return int(self.limits["max_hosts"])

    def summary(self) -> str:
        if self.tier == "free":
            head = "Free (no licence installed)"
        else:
            state = "EXPIRED" if self.is_expired else f"valid, {self.days_left} day(s) left" \
                if self.days_left is not None else "valid, no expiry"
            head = f"{self.limits['label']} — {state}"
            if self.customer:
                head += f" — {self.customer}"
        lines = [f"licence : {head}"]
        lines.append(f"checks  : {', '.join(self.limits['checks'])}")
        lines.append(f"reports : {', '.join(self.limits['reports'])}")
        limit = self.host_limit()
        lines.append(f"hosts   : {'unlimited' if limit == 0 else limit}")
        if self.order:
            lines.append(f"order   : {self.order}")
        if self.machine:
            lines.append(f"bound to: {self.machine}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# the secret
# ---------------------------------------------------------------------------
def secret_path(home: Optional[pathlib.Path] = None) -> pathlib.Path:
    root = pathlib.Path(home) if home else pathlib.Path.home() / ".pentdeck"
    return root / "secret"


def load_secret(home: Optional[pathlib.Path] = None, required: bool = True) -> str:
    """The signing secret: environment first, then a file, then fail loudly."""
    value = os.environ.get(SECRET_ENV, "").strip()
    if value:
        return value
    path = secret_path(home)
    if path.is_file():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    if not required:
        return ""
    raise LicenseError(
        f"no licence signing secret. Set {SECRET_ENV}, or write one to {path} (mode 0600).\n"
        "Generate one with:  python3 -c \"import secrets;print(secrets.token_urlsafe(32))\"\n"
        "The same secret must be used when issuing and when verifying."
    )


def save_secret(secret: str, home: Optional[pathlib.Path] = None) -> pathlib.Path:
    if len(secret) < 16:
        raise LicenseError("a signing secret shorter than 16 characters is asking for trouble")
    path = secret_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(secret + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


# ---------------------------------------------------------------------------
# machine binding
# ---------------------------------------------------------------------------
def machine_id() -> str:
    """A short, stable id for this machine.

    Built from the hostname and the MAC address, hashed — so the licence file
    contains something that identifies a machine without recording anything
    personal about it, and without a hardware fingerprint that survives a reinstall.
    """
    pieces = [platform.node(), str(uuid.getnode()), sys.platform]
    digest = hashlib.sha256("|".join(pieces).encode()).hexdigest()
    return digest[:12]


def machine_file(home: Optional[pathlib.Path] = None) -> pathlib.Path:
    root = pathlib.Path(home) if home else pathlib.Path.home() / ".pentdeck"
    return root / MACHINE_FILENAME


# ---------------------------------------------------------------------------
# tokens
# ---------------------------------------------------------------------------
def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except Exception as exc:                               # noqa: BLE001 - any shape of garbage
        raise LicenseError("the token is not valid base64") from exc


def _sign(secret: str, payload_b64: str) -> str:
    digest = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).digest()
    return _b64(digest)


def issue_token(
    secret: str,
    customer: str,
    tier: str = "pro",
    days: Optional[int] = 3650,
    order: str = "",
    machine: str = "",
    seats: int = 1,
    now: Optional[datetime.datetime] = None,
) -> str:
    """Create a signed licence token. This is the vendor-side operation."""
    if tier not in TIERS:
        raise LicenseError(f"unknown tier {tier!r} — pick one of {', '.join(sorted(TIERS))}")
    customer = customer.strip()
    if not customer:
        raise LicenseError("a licence needs a customer name; an anonymous licence is not a record")
    if days is not None and days <= 0:
        raise LicenseError("days must be positive (use None for a licence that never expires)")
    moment = now or datetime.datetime.now(datetime.timezone.utc)
    payload: Dict[str, Any] = {
        "v": 1,
        "customer": customer,
        "tier": tier,
        "issued": moment.isoformat(),
        "order": order.strip(),
        "seats": int(seats),
        "machine": machine.strip(),
        "expires": (moment + datetime.timedelta(days=days)).isoformat() if days else None,
        "nonce": secrets.token_hex(4),
    }
    encoded = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    return f"{TOKEN_PREFIX}.{encoded}.{_sign(secret, encoded)}"


def decode_token(token: str, secret: str, machine: str = "", enforce_machine: bool = True) -> License:
    """Verify a token and return the licence, or raise LicenseError."""
    text = (token or "").strip().replace("\n", "").replace(" ", "")
    parts = text.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise LicenseError("that does not look like a pentdeck licence token (expected PD1.… .…)")
    _, encoded, signature = parts
    expected = _sign(secret, encoded)
    if not hmac.compare_digest(expected, signature):
        raise LicenseError(
            "the licence signature does not match this build's secret — either the token was "
            "altered, or it was issued with a different signing secret"
        )
    try:
        payload = json.loads(_unb64(encoded))
    except json.JSONDecodeError as exc:
        raise LicenseError(f"the licence payload is not readable: {exc}") from exc
    if not isinstance(payload, dict):
        raise LicenseError("the licence payload is not an object")

    license_ = License(
        customer=str(payload.get("customer", "")),
        tier=str(payload.get("tier", "free")),
        order=str(payload.get("order", "")),
        issued=str(payload.get("issued", "")),
        expires=payload.get("expires"),
        machine=str(payload.get("machine", "")),
        seats=int(payload.get("seats", 1) or 1),
        token=text,
    )
    if license_.tier not in TIERS:
        raise LicenseError(f"the licence names an unknown tier {license_.tier!r}")
    if enforce_machine and license_.machine:
        here = machine or machine_id()
        if license_.machine != here:
            raise LicenseError(
                f"this licence is bound to machine {license_.machine} and this machine is {here} — "
                f"ask for it to be reissued for this machine"
            )
    return license_


def inspect_token(token: str) -> Dict[str, Any]:
    """Read a token without verifying it — for showing the user what they pasted."""
    parts = (token or "").strip().split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise LicenseError("that does not look like a pentdeck licence token")
    try:
        payload = json.loads(_unb64(parts[1]))
    except (LicenseError, json.JSONDecodeError) as exc:
        raise LicenseError(f"cannot read the payload: {exc}") from exc
    if not isinstance(payload, dict):
        raise LicenseError("the payload is not an object")
    return payload


# ---------------------------------------------------------------------------
# installation
# ---------------------------------------------------------------------------
def license_file(home: Optional[pathlib.Path] = None) -> pathlib.Path:
    root = pathlib.Path(home) if home else pathlib.Path.home() / ".pentdeck"
    return root / LICENSE_FILENAME


def install_token(token: str, home: Optional[pathlib.Path] = None, secret: str = "") -> License:
    """Verify and store a token. Nothing lands on disk unless it verifies."""
    secret = secret or load_secret(home)
    license_ = decode_token(token, secret)
    path = license_file(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"token": license_.token, "installed": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return license_


def current_license(home: Optional[pathlib.Path] = None, secret: str = "") -> License:
    """The installed licence, or the free tier when there is none.

    A licence that fails to verify is reported as free rather than crashing the
    tool — the customer still gets the free tools, plus a clear warning.
    """
    path = license_file(home)
    if not path.is_file():
        return License(tier="free")
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
        token = str(stored.get("token", ""))
    except (OSError, json.JSONDecodeError):
        return License(tier="free")
    resolved = secret or load_secret(home, required=False)
    if not resolved:
        return License(tier="free")
    try:
        return decode_token(token, resolved)
    except LicenseError:
        return License(tier="free")


def upgrade_message(tier: str = "pro", wallet: str = "", telegram: str = "") -> str:
    """The block shown to a free user who asks for more."""
    limits = TIERS.get(tier, TIERS["pro"])
    lines = [
        f"Unlock {limits['label']} — ${limits['price_usd']} once, no subscription:",
        "  • every check, including the ones marked intrusive",
        "  • HTML, JSON and Markdown reports you can hand to a client",
        "  • no host limit (Free stops at 16) and support",
        "",
        "How to buy:",
        "  1. pentdeck license request --name \"Your Name\" --email you@example.com --tier pro",
        "  2. you get an order code and the wallet address",
        f"  3. pay ${limits['price_usd']} in USDT (TRC20) with the order code in the memo",
        "  4. the licence token arrives in the same chat — install it with:",
        "       pentdeck license install <TOKEN>",
    ]
    if wallet:
        lines.append("")
        lines.append(f"wallet (USDT, TRC20): {wallet}")
    if telegram:
        lines.append(f"questions: {telegram}")
    return "\n".join(lines)


def seat_check(license_: License, seats_in_use: int) -> None:
    """Team is sold per number of operators."""
    if seats_in_use > int(license_.seats):
        raise LicenseError(
            f"this licence is for {license_.seats} operator(s) and {seats_in_use} are recorded — "
            f"ask for a Team licence"
        )
