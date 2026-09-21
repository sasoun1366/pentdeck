"""The scan engine.

One host at a time in parallel, one check at a time per host, in a fixed order:
ports, then banners, then the checks that need to know what is listening. That
order matters — it is what keeps a scan quick and keeps the findings honest
(you cannot audit the TLS on a port you have not found yet).

Three things are enforced here rather than trusted to the caller:

* every host is re-checked against the scope before a packet is sent;
* checks the licence does not include, and intrusive checks without `--intrusive`,
  are recorded as *skipped* — the report says what was not done, which is as
  important as what was;
* the host limit of the licence is applied before the scan starts, not half-way
  through it.
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import datetime
import pathlib
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .checks import CHECKS, ORDER, Check, CheckContext
from .findings import Finding, ScanResult, Severity, deduplicate
from .license import License
from .scope import (DEFAULT_PORTS, AuditLog, Scope, ScopeError, require_authorization,
                    split_host_port)


def _stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


#: Called as the scan moves along: ``progress("host", {...})``. The desktop app
#: draws its log from this; a caller that passes nothing pays nothing.
Progress = Callable[[str, Dict[str, object]], None]


def _emit(progress: Optional[Progress], event: str, **fields: object) -> None:
    """A progress callback must never be able to kill a scan."""
    if progress is None:
        return
    try:
        progress(event, fields)
    except Exception:                                     # noqa: BLE001
        pass


@dataclasses.dataclass
class ScanOptions:
    """Everything the user chose for this run."""

    ports: Sequence[int] = DEFAULT_PORTS
    intrusive: bool = False
    timeout: float = 5.0
    host_workers: int = 8
    port_workers: int = 64
    #: Seconds to wait between hosts. A slower scan is a scan that does not trip
    #: an intrusion-detection system or knock over a small router.
    host_delay: float = 0.0
    #: Restrict to these check names (the licence still has the last word).
    only: Sequence[str] = ()
    skip: Sequence[str] = ()
    operator: str = ""
    reference: str = ""

    def wants(self, check: Check) -> bool:
        if self.only and check.name not in self.only:
            return False
        if check.name in self.skip:
            return False
        return True


def plan_checks(license_: License, options: ScanOptions) -> Tuple[List[Check], List[Tuple[str, str]]]:
    """Which checks will run, and why the others will not."""
    will_run: List[Check] = []
    skipped: List[Tuple[str, str]] = []
    for name in ORDER:
        check = CHECKS[name]
        if not options.wants(check):
            skipped.append((name, "not requested for this run"))
            continue
        if check.intrusive and not options.intrusive:
            skipped.append((name, "intrusive check — add --intrusive"))
            continue
        if check.intrusive and not license_.allows_intrusive():
            skipped.append((name, "intrusive check — needs a paid licence"))
            continue
        if not license_.allows_check(name):
            skipped.append((name, f"not in the {license_.tier} licence"))
            continue
        will_run.append(check)
    return will_run, skipped


def scan_host(host: str, checks: Sequence[Check], options: ScanOptions,
              audit: Optional[AuditLog] = None, scope_name: str = "") -> Tuple[List[Finding], Dict[str, object]]:
    """Run the checks for one host. Returns (findings, stats).

    The host may arrive as "10.0.0.5:8443" when the scope entry named a port; that
    port is added to the list for this host only, so the rest of the run keeps the
    ports the user asked for.
    """
    bare_host, own_port = split_host_port(host, None)
    port_list = list(options.ports)
    if own_port and own_port not in port_list:
        port_list.append(own_port)
    context = CheckContext(
        host=bare_host,
        ports=port_list,
        timeout=options.timeout,
        intrusive=options.intrusive,
        port_workers=options.port_workers,
    )
    findings: List[Finding] = []
    stats: Dict[str, object] = {"host": host, "open_ports": [], "errors": [], "checks": []}

    for check in checks:
        if check.needs_open_port and not context.open_ports and check.stage > 1:
            continue
        started = time.monotonic()
        try:
            findings.extend(check.run(context))
            stats["checks"].append(check.name)          # type: ignore[union-attr]
        except Exception as exc:                        # noqa: BLE001 - a broken check must not end the scan
            stats["errors"].append(f"{check.name}: {type(exc).__name__}: {exc}")  # type: ignore[union-attr]
        finally:
            if audit is not None:
                audit.append(
                    "check",
                    scope=scope_name,
                    host=host,
                    check=check.name,
                    seconds=round(time.monotonic() - started, 2),
                    open_ports=list(context.open_ports),
                )
    stats["open_ports"] = list(context.open_ports)
    stats["banners"] = dict(context.banners)
    return findings, stats


def run_scan(scope: Scope, license_: License, options: Optional[ScanOptions] = None,
             home: Optional[pathlib.Path] = None, progress: Optional[Progress] = None,
             should_stop: Optional[Callable[[], bool]] = None) -> ScanResult:
    """Scan the scope. Raises ScopeError when the run is not allowed at all."""
    options = options or ScanOptions()
    home = pathlib.Path(home) if home else pathlib.Path.home() / ".pentdeck"
    audit = AuditLog(home)

    authorization = require_authorization(scope, options.operator or None, options.reference or None)
    hosts = scope.hosts()
    if not hosts:
        raise ScopeError(f"scope {scope.name!r} has no targets — add one with `pentdeck scope add`")
    limit = license_.host_limit()
    if limit and len(hosts) > limit:
        raise ScopeError(
            f"this scope has {len(hosts)} hosts and the {license_.tier} licence allows {limit}. "
            f"Scan a smaller range, or upgrade (`pentdeck license request`)."
        )
    for host in hosts:                                   # defence in depth: the scope has the last word
        scope.check(host)

    checks, skipped = plan_checks(license_, options)

    result = ScanResult(
        scope_name=scope.name,
        authorization=authorization.summary(),
        started=_stamp(),
        hosts_total=len(hosts),
        license_tier=license_.tier,
        tool_version=__version__,
        checks_skipped=skipped,
    )
    result.checks_run = [check.name for check in checks]

    audit.append(
        "scan-start",
        scope=scope.name,
        operator=authorization.operator,
        reference=authorization.reference,
        hosts=len(hosts),
        checks=result.checks_run,
        intrusive=options.intrusive,
        tier=license_.tier,
    )
    if options.only:
        audit.append("scan-options", only=list(options.only), skip=list(options.skip), ports=len(options.ports))

    started = time.monotonic()
    _emit(progress, "start", scope=scope.name, hosts=len(hosts), checks=result.checks_run,
          skipped=[name for name, _ in skipped], ports=len(options.ports), intrusive=options.intrusive)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, options.host_workers)) as pool:
        futures = {}
        for index, host in enumerate(hosts):
            if options.host_delay and index:
                time.sleep(options.host_delay * index if options.host_workers == 1 else options.host_delay)
            futures[pool.submit(scan_host, host, checks, options, audit, scope.name)] = host
        stopped = False
        for future in concurrent.futures.as_completed(futures):
            if should_stop is not None and should_stop():
                stopped = True
                for pending in futures:
                    pending.cancel()
                break
            host = futures[future]
            try:
                findings, stats = future.result()
            except Exception as exc:                     # noqa: BLE001
                result.errors.append(f"{host}: {type(exc).__name__}: {exc}")
                _emit(progress, "host", host=host, up=False, ports=0, findings=0,
                      error=f"{type(exc).__name__}: {exc}")
                continue
            result.findings.extend(findings)
            result.hosts_scanned.append(host)
            if stats["open_ports"]:
                result.hosts_up.append(host)             # type: ignore[arg-type]
            for problem in stats["errors"]:              # type: ignore[union-attr]
                result.errors.append(f"{host}: {problem}")
            _emit(progress, "host", host=host, up=bool(stats["open_ports"]),
                  ports=len(stats["open_ports"]),                       # type: ignore[arg-type]
                  findings=len(findings), checks=len(stats["checks"]),  # type: ignore[arg-type]
                  errors=list(stats["errors"]))                          # type: ignore[arg-type]
        result.interrupted = stopped
        if stopped:
            audit.append("scan-stopped", scope=scope.name, scanned=len(result.hosts_scanned))
            _emit(progress, "stopped", scanned=len(result.hosts_scanned))

    result.findings = deduplicate(result.findings)
    result.finished = _stamp()
    result.hosts_up.sort()
    result.hosts_scanned.sort()
    audit.append(
        "scan-end",
        scope=scope.name,
        seconds=round(time.monotonic() - started, 2),
        hosts_up=len(result.hosts_up),
        findings=len(result.findings),
        worst=result.worst.value,
        interrupted=result.interrupted,
    )
    _emit(progress, "end", findings=len(result.findings), worst=result.worst.value,
          hosts_up=len(result.hosts_up), errors=len(result.errors),
          seconds=round(time.monotonic() - started, 2))
    return result


def worst_finding(result: ScanResult, minimum: Severity = Severity.INFO) -> Optional[Finding]:
    for finding in result.sorted_findings(minimum):
        return finding
    return None
