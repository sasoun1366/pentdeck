"""Target scope, authorization and the audit trail.

Every serious question about a scanning tool is answered here: which systems may
be touched, on whose authority, and what exactly happened afterwards.

Three rules are enforced in code rather than in a document:

1. A scan needs a scope. Anything outside it is refused, not just discouraged.
2. A scope needs an authorization record: an operator and a reference to the
   permission (a contract number, an e-mail, a ticket). This is what the client's
   legal team asks for, and it is what protects the operator.
3. Every action is appended to an audit log, so the report can state what was
   done, by whom, when — including the checks that found nothing.
"""

from __future__ import annotations

import dataclasses
import datetime
import ipaddress
import json
import os
import pathlib
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SCOPE_FILENAME = "scope.json"
AUDIT_FILENAME = "audit.jsonl"

#: A /24 is 256 hosts; refusing to expand anything past this stops one typo
#: ("10.0.0.0/8") from turning into a scan of sixteen million addresses.
MAX_HOSTS_PER_ENTRY = 1024
MAX_HOSTS_TOTAL = 4096

#: Ports that are worth looking at first when nothing else is given.
DEFAULT_PORTS: Tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 631, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5060, 5432,
    5900, 5985, 6379, 8006, 8080, 8443, 8728, 8729, 9200, 11211, 27017,
)
TOP_PORTS: Tuple[int, ...] = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080)


class ScopeError(ValueError):
    """A scope or authorization problem the user can fix."""


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ---------------------------------------------------------------------------
# hosts
# ---------------------------------------------------------------------------
def is_public(host: str) -> bool:
    """True when the address is routable on the internet.

    Names are never 'public' by this function — only resolved addresses are, and
    this module deliberately does not resolve anything (that would make scope
    checks depend on DNS).
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local
                or address.is_reserved or address.is_multicast or address.is_unspecified)


#: A DNS label as RFC 1123 allows it. Deliberately strict: a scope entry that cannot
#: resolve is not a scan that skipped a host, it is a report nobody can trust.
_LABEL = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$")


def valid_target_name(entry: str) -> bool:
    """True for an IP address (v4/v6, optionally bracketed) or a plausible DNS name."""
    text = entry.strip()
    if not text:
        return False
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        pass
    core = text[:-1] if text.endswith(".") else text
    if len(core) > 253:
        return False
    labels = core.split(".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        return False
    return all(_LABEL.match(label) for label in labels)


def looks_like_a_name(entry: str) -> bool:
    try:
        ipaddress.ip_address(entry)
        return False
    except ValueError:
        return True


def expand_entry(entry: str, limit: int = MAX_HOSTS_PER_ENTRY) -> List[str]:
    """Expand one scope entry into bare hosts.

    Accepts `host`, `host:port`, `10.0.0.0/24`, `10.0.0.10-20`, and `10.0.0.10-10.0.0.20`.
    A port, when given, is returned as `host:port` so the caller can honour it.
    """
    text = entry.strip()
    if not text or text.startswith("#"):
        return []
    port = ""
    if text.startswith("[") and "]:" in text:                # [fe80::1]:8443
        head, _, tail = text.partition("]:")
        if tail.strip().isdigit():
            text, port = head.strip() + "]", f":{int(tail)}"
    elif text.count(":") == 1 and not text.split(":")[1].strip().startswith("/"):
        head, _, tail = text.partition(":")
        if tail.strip().isdigit():
            text, port = head.strip(), f":{int(tail)}"
    if port and not looks_like_a_name(text):
        pass

    if "/" in text:                                        # a CIDR block
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ScopeError(f"{entry!r}: {exc}") from exc
        hosts = [str(host) for host in network.hosts()]
        if not hosts:                                      # a /31 or /32
            hosts = [str(network.network_address)]
        if len(hosts) > limit:
            raise ScopeError(
                f"{entry!r} expands to {len(hosts)} addresses, more than the {limit} allowed here — "
                f"narrow the range or raise the limit deliberately"
            )
        return [host + port for host in hosts]

    if "-" in text and not looks_like_a_name(text.split("-")[0]):
        start_text, _, end_text = text.partition("-")
        if "." in end_text:                                # 10.0.0.10-10.0.0.20
            try:
                start, end = ipaddress.ip_address(start_text.strip()), ipaddress.ip_address(end_text.strip())
            except ValueError as exc:
                raise ScopeError(f"{entry!r}: {exc}") from exc
        else:                                              # 10.0.0.10-20
            end_text = end_text.strip()
            if not end_text.isdigit():
                raise ScopeError(f"{entry!r} is not a range I understand")
            start, end = ipaddress.ip_address(start_text.strip()), None
            octets = str(start).split(".")
            octets[-1] = end_text
            end = ipaddress.ip_address(".".join(octets))
        if int(end) < int(start):
            raise ScopeError(f"{entry!r}: the range ends before it starts")
        if end.version != start.version:
            raise ScopeError(f"{entry!r}: the two ends are different address families")
        count = int(end) - int(start) + 1
        if count > limit:
            raise ScopeError(f"{entry!r} expands to {count} addresses, more than the {limit} allowed here")
        return [str(ipaddress.ip_address(int(start) + offset)) + port for offset in range(count)]

    if not valid_target_name(text):
        raise ScopeError(
            f"{entry!r} is not something I would scan — expected an address, a CIDR block, "
            f"a range, or a name like srv-01.example.lan"
        )
    return [text + port]


def split_host_port(target: str, default_port: Optional[int] = None) -> Tuple[str, Optional[int]]:
    """`10.0.0.5:8443` -> ('10.0.0.5', 8443). Bracketed IPv6 also works."""
    text = target.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest.startswith(":") and rest[1:].strip().isdigit():
            return host, int(rest[1:])
        return host, default_port
    if text.count(":") == 1:
        head, _, tail = text.partition(":")
        if tail.strip().isdigit():
            return head.strip(), int(tail)
    return text, default_port


# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class Authorization:
    """Who is doing this, and on whose written authority."""

    operator: str
    reference: str
    note: str = ""
    authorized_on: str = ""

    def __post_init__(self) -> None:
        self.operator = self.operator.strip()
        self.reference = self.reference.strip()
        if not self.operator:
            raise ScopeError("authorization needs an operator name")
        if not self.reference:
            raise ScopeError(
                "authorization needs a reference to the permission — a contract number, "
                "an approval e-mail, or a ticket id"
            )
        if not self.authorized_on:
            self.authorized_on = _now().isoformat()

    def summary(self) -> str:
        return (f"{self.operator} — authority: {self.reference} "
                f"(recorded {self.authorized_on[:19]}Z)")


@dataclasses.dataclass
class Scope:
    """The list of things that may be scanned."""

    name: str = "default"
    entries: List[str] = dataclasses.field(default_factory=list)
    allow_public: bool = False
    authorization: Optional[Authorization] = None
    deny: List[str] = dataclasses.field(default_factory=list)

    # ── hosts ────────────────────────────────────────────────────────────────
    def hosts(self, limit: int = MAX_HOSTS_TOTAL) -> List[str]:
        """Every host in the scope, expanded and de-duplicated, in order."""
        expanded: List[str] = []
        seen = set()
        for entry in self.entries:
            for host in expand_entry(entry):
                if host not in seen:
                    seen.add(host)
                    expanded.append(host)
        if len(expanded) > limit:
            raise ScopeError(f"the scope expands to {len(expanded)} hosts, more than the {limit} allowed")
        return expanded

    def denylist(self) -> List[str]:
        out: List[str] = []
        for entry in self.deny:
            out.extend(expand_entry(entry))
        return out

    def check(self, target: str) -> None:
        """Raise ScopeError unless this target may be touched."""
        host, port = split_host_port(target)
        deny_hosts = {split_host_port(item)[0] for item in self.denylist()}
        if host in deny_hosts:
            raise ScopeError(f"{host} is on the deny list for scope {self.name!r}")
        allowed = {split_host_port(item)[0] for item in self.hosts()}
        if host not in allowed:
            raise ScopeError(
                f"{host} is not in scope {self.name!r} — add it first "
                f"(`pentdeck scope add {host}`), or the scan would touch a system "
                f"you have no permission to test"
            )
        if is_public(host) and not self.allow_public:
            raise ScopeError(
                f"{host} is a public address and this scope has allow_public=false — "
                f"set it deliberately if you really are authorised for it"
            )

    # ── disk ─────────────────────────────────────────────────────────────────
    @classmethod
    def path(cls, home: pathlib.Path) -> pathlib.Path:
        return pathlib.Path(home) / SCOPE_FILENAME

    @classmethod
    def load(cls, home: pathlib.Path) -> "Scope":
        path = cls.path(home)
        if not path.is_file():
            raise ScopeError(f"no scope yet — create one with `pentdeck scope init` ({path})")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ScopeError(f"{path} is not valid JSON: {exc}") from exc
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: Dict[str, object]) -> "Scope":
        if not isinstance(raw, dict):
            raise ScopeError("the scope file must contain an object")
        authorization = raw.get("authorization")
        return cls(
            name=str(raw.get("name") or "default"),
            entries=[str(item) for item in (raw.get("entries") or [])],
            allow_public=bool(raw.get("allow_public", False)),
            deny=[str(item) for item in (raw.get("deny") or [])],
            authorization=Authorization(**authorization) if authorization else None,
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "entries": list(self.entries),
            "deny": list(self.deny),
            "allow_public": self.allow_public,
            "authorization": dataclasses.asdict(self.authorization) if self.authorization else None,
        }

    def save(self, home: pathlib.Path) -> pathlib.Path:
        path = self.path(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        return path

    # ── editing ──────────────────────────────────────────────────────────────
    def add(self, entry: str) -> None:
        if not entry.strip():
            raise ScopeError("nothing to add")
        expand_entry(entry)                                # validate before storing
        if entry.strip() not in self.entries:
            self.entries.append(entry.strip())

    def remove(self, entry: str) -> bool:
        if entry.strip() in self.entries:
            self.entries.remove(entry.strip())
            return True
        return False

    def summary(self) -> str:
        lines = [f"scope      : {self.name}"]
        if self.authorization:
            lines.append(f"authorized : {self.authorization.summary()}")
        else:
            lines.append("authorized : NOT RECORDED — a scan will refuse to run")
        try:
            hosts = self.hosts()
        except ScopeError as exc:
            return "\n".join(lines + [f"targets    : invalid ({exc})"])
        lines.append(f"targets    : {len(hosts)} host(s) from {len(self.entries)} entr(y/ies)")
        for entry in self.entries:
            lines.append(f"               {entry}")
        if self.deny:
            lines.append(f"deny       : {', '.join(self.deny)}")
        if self.allow_public:
            lines.append("allow_public: true — public addresses will be scanned")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# the audit trail
# ---------------------------------------------------------------------------
class AuditLog:
    """Append-only JSONL. Records what was touched, by whom, and when."""

    def __init__(self, home: pathlib.Path):
        self.path = pathlib.Path(home) / AUDIT_FILENAME

    def append(self, event: str, **fields: object) -> Dict[str, object]:
        record: Dict[str, object] = {"time": _now().isoformat(), "event": event}
        record.update(fields)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str) + "\n")
            os.chmod(self.path, 0o600)
        except OSError:
            pass                                           # an unwritable log must not stop a scan
        return record

    def tail(self, limit: int = 20) -> List[Dict[str, object]]:
        if not self.path.is_file():
            return []
        out: List[Dict[str, object]] = []
        for line in reversed(self.path.read_text(encoding="utf-8").splitlines()[-1000:]):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(out) >= limit:
                break
        return out


def require_authorization(scope: Scope, operator: Optional[str] = None,
                          reference: Optional[str] = None) -> Authorization:
    """Return the authorization to use, or explain what is missing.

    `--i-am-authorized-by` on the command line fills in gaps for one run without
    editing the scope file, but the record is still written to the audit log.
    """
    if scope.authorization is not None and not (operator or reference):
        return scope.authorization
    who = (operator or (scope.authorization.operator if scope.authorization else "") or "").strip()
    why = (reference or (scope.authorization.reference if scope.authorization else "") or "").strip()
    if not who or not why:
        raise ScopeError(
            "this scan has no recorded authorization. A pentest tool that will scan "
            "anything you type is a liability, so pentdeck asks for two things first:\n"
            "    pentdeck authorize --operator \"Your Name\" --reference \"contract #123\"\n"
            "or, for a single run: --operator NAME --reference REF"
        )
    return Authorization(operator=who, reference=why)


def summarize_hosts(hosts: Sequence[str], limit: int = 8) -> str:
    """'10.0.0.1, 10.0.0.2 … (+14 more)' — for one-line messages."""
    shown = ", ".join(hosts[:limit])
    rest = len(hosts) - limit
    return f"{shown} (+{rest} more)" if rest > 0 else shown
