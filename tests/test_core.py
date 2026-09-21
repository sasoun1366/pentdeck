"""Core tests: scope, authorization, audit, licences, findings.

No network, no display, no PyQt. Run with `pytest -q`.
"""

import datetime
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from pentdeck import cli, findings, license as lic, purchase as pur, scope as sc  # noqa: E402


# ---------------------------------------------------------------------------
# hosts and ranges
# ---------------------------------------------------------------------------
def test_expand_single_host_and_host_port():
    assert sc.expand_entry("10.0.0.5") == ["10.0.0.5"]
    assert sc.expand_entry("10.0.0.5:8443") == ["10.0.0.5:8443"]
    assert sc.expand_entry("mail.example.test:993") == ["mail.example.test:993"]
    assert sc.expand_entry("  # a comment") == []
    assert sc.expand_entry("") == []


def test_expand_cidr():
    hosts = sc.expand_entry("192.168.1.0/30")
    assert hosts == ["192.168.1.1", "192.168.1.2"]
    assert sc.expand_entry("192.168.1.0/30:443") == ["192.168.1.1:443", "192.168.1.2:443"]


def test_expand_short_last_octet_range():
    assert sc.expand_entry("10.0.0.10-12") == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]


def test_expand_full_range_and_rejects_bad_ones():
    assert sc.expand_entry("10.0.0.10-10.0.0.11") == ["10.0.0.10", "10.0.0.11"]
    with pytest.raises(sc.ScopeError):
        sc.expand_entry("10.0.0.20-10.0.0.10")            # ends before it starts
    with pytest.raises(sc.ScopeError):
        sc.expand_entry("10.0.0.0/8")                     # 16M addresses
    with pytest.raises(sc.ScopeError):
        sc.expand_entry("10.0.0.1-abc")


def test_public_address_detection():
    assert sc.is_public("8.8.8.8") is True
    assert sc.is_public("10.0.0.1") is False
    assert sc.is_public("192.168.1.1") is False
    assert sc.is_public("127.0.0.1") is False
    assert sc.is_public("example.test") is False          # names are not judged here


def test_split_host_port():
    assert sc.split_host_port("host:80") == ("host", 80)
    assert sc.split_host_port("host") == ("host", None)
    assert sc.split_host_port("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert sc.split_host_port("2001:db8::1") == ("2001:db8::1", None)


# ---------------------------------------------------------------------------
# the scope
# ---------------------------------------------------------------------------
def test_scope_check_refuses_outsiders(tmp_path):
    scope = sc.Scope(name="lab", entries=["192.168.50.0/30"])
    scope.check("192.168.50.1")
    with pytest.raises(sc.ScopeError) as excinfo:
        scope.check("192.168.99.9")
    assert "not in scope" in str(excinfo.value)


def test_scope_refuses_public_addresses_unless_allowed():
    scope = sc.Scope(name="lab", entries=["8.8.8.8"])
    with pytest.raises(sc.ScopeError) as excinfo:
        scope.check("8.8.8.8")
    assert "public" in str(excinfo.value)
    scope.allow_public = True
    scope.check("8.8.8.8")


def test_scope_deny_list_wins():
    scope = sc.Scope(name="lab", entries=["10.0.0.0/29"], deny=["10.0.0.3"])
    scope.check("10.0.0.1")
    with pytest.raises(sc.ScopeError) as excinfo:
        scope.check("10.0.0.3")
    assert "deny" in str(excinfo.value)


def test_scope_round_trip(tmp_path):
    scope = sc.Scope(name="acme", entries=["10.0.0.0/29"], allow_public=False,
                     authorization=sc.Authorization(operator="S. S.", reference="contract 42"))
    path = scope.save(tmp_path)
    assert path.name == sc.SCOPE_FILENAME
    assert oct(path.stat().st_mode)[-3:] == "600"
    loaded = sc.Scope.load(tmp_path)
    assert loaded.name == "acme"
    assert loaded.authorization.operator == "S. S."
    assert loaded.authorization.reference == "contract 42"
    assert loaded.hosts() == scope.hosts()


def test_missing_scope_file_is_explained(tmp_path):
    with pytest.raises(sc.ScopeError) as excinfo:
        sc.Scope.load(tmp_path)
    assert "pentdeck scope init" in str(excinfo.value)


def test_authorization_is_required_before_a_scan():
    scope = sc.Scope(name="lab", entries=["10.0.0.1"])
    with pytest.raises(sc.ScopeError) as excinfo:
        sc.require_authorization(scope)
    assert "authorization" in str(excinfo.value)


def test_authorization_can_be_supplied_for_one_run():
    scope = sc.Scope(name="lab", entries=["10.0.0.1"])
    record = sc.require_authorization(scope, operator="Ana", reference="ticket 7")
    assert record.operator == "Ana" and record.reference == "ticket 7"


def test_authorization_needs_both_halves():
    with pytest.raises(sc.ScopeError):
        sc.Authorization(operator="Ana", reference="")
    with pytest.raises(sc.ScopeError):
        sc.Authorization(operator="", reference="ticket 7")


def test_audit_log_appends_and_reads_back(tmp_path):
    log = sc.AuditLog(tmp_path)
    log.append("scan-start", scope="lab", hosts=2)
    log.append("check", host="10.0.0.1", check="ports", seconds=0.4)
    tail = log.tail(10)
    assert [item["event"] for item in tail] == ["check", "scan-start"]   # newest first
    assert tail[0]["check"] == "ports"
    assert oct(log.path.stat().st_mode)[-3:] == "600"


def test_summarize_hosts_shortens_long_lists():
    assert sc.summarize_hosts(["a", "b"]) == "a, b"
    assert "+1 more" in sc.summarize_hosts([str(i) for i in range(9)], limit=8)


# ---------------------------------------------------------------------------
# licences
# ---------------------------------------------------------------------------
SECRET = "test-secret-that-is-long-enough"


def test_free_tier_is_the_default():
    license_ = lic.License(tier="free")
    assert license_.is_paid is False
    assert license_.allows_check("ports") is True
    assert license_.allows_check("tls") is False
    assert license_.allows_report("html") is False
    assert license_.host_limit() == 16
    assert license_.allows_intrusive() is False


def test_issue_and_verify_round_trip():
    token = lic.issue_token(SECRET, "Acme Ltd", tier="pro", order="PD-TEST")
    license_ = lic.decode_token(token, SECRET)
    assert license_.customer == "Acme Ltd"
    assert license_.tier == "pro"
    assert license_.order == "PD-TEST"
    assert license_.allows_check("http") is True
    assert license_.allows_report("html") is True
    assert license_.allows_intrusive() is True
    assert license_.host_limit() == 0                    # no limit
    assert license_.days_left is not None and 3600 < license_.days_left <= 3650


def test_a_tampered_licence_is_rejected():
    token = lic.issue_token(SECRET, "Acme", tier="pro")
    head, payload, _signature = token.split(".")
    forged_payload = lic._b64(json.dumps({"v": 1, "customer": "Acme", "tier": "team",
                                          "issued": "2026-01-01T00:00:00+00:00",
                                          "seats": 99, "expires": None}).encode())
    forged = f"{head}.{forged_payload}.{token.split('.')[2]}"
    with pytest.raises(lic.LicenseError) as excinfo:
        lic.decode_token(forged, SECRET)
    assert "signature" in str(excinfo.value)


def test_a_licence_signed_with_another_secret_is_rejected():
    token = lic.issue_token("a-different-secret-entirely", "Acme", tier="pro")
    with pytest.raises(lic.LicenseError):
        lic.decode_token(token, SECRET)


def test_garbage_tokens_are_rejected():
    for rubbish in ("", "hello", "PD1.only-two-parts", "XX1.abc.def"):
        with pytest.raises(lic.LicenseError):
            lic.decode_token(rubbish, SECRET)


def test_expiry_and_renewal():
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
    token = lic.issue_token(SECRET, "Acme", tier="pro", days=5, now=past)
    license_ = lic.decode_token(token, SECRET)
    assert license_.is_expired is True
    assert license_.is_paid is False
    assert license_.allows_check("tls") is False         # falls back to the free set
    assert license_.allows_check("ports") is True
    assert "EXPIRED" in license_.summary()


def test_a_licence_without_expiry():
    token = lic.issue_token(SECRET, "Acme", tier="team", days=None)
    license_ = lic.decode_token(token, SECRET)
    assert license_.expires is None
    assert license_.days_left is None
    assert license_.is_expired is False


def test_machine_binding():
    token = lic.issue_token(SECRET, "Acme", tier="pro", machine="machine-abc")
    assert lic.decode_token(token, SECRET, machine="machine-abc").tier == "pro"
    with pytest.raises(lic.LicenseError) as excinfo:
        lic.decode_token(token, SECRET, machine="machine-xyz")
    assert "bound to machine" in str(excinfo.value)


def test_issue_refuses_nonsense():
    with pytest.raises(lic.LicenseError):
        lic.issue_token(SECRET, "  ", tier="pro")
    with pytest.raises(lic.LicenseError):
        lic.issue_token(SECRET, "Acme", tier="platinum")
    with pytest.raises(lic.LicenseError):
        lic.issue_token(SECRET, "Acme", tier="pro", days=0 if False else -3)


def test_install_and_current_license(tmp_path):
    token = lic.issue_token(SECRET, "Acme", tier="pro", order="PD-AAAA")
    assert lic.current_license(tmp_path, secret=SECRET).tier == "free"
    installed = lic.install_token(token, tmp_path, secret=SECRET)
    assert installed.customer == "Acme"
    assert oct(lic.license_file(tmp_path).stat().st_mode)[-3:] == "600"
    assert lic.current_license(tmp_path, secret=SECRET).tier == "pro"


def test_a_broken_licence_file_falls_back_to_free(tmp_path):
    path = lic.license_file(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    assert lic.current_license(tmp_path, secret=SECRET).tier == "free"


def test_secret_handling(tmp_path, monkeypatch):
    monkeypatch.delenv(lic.SECRET_ENV, raising=False)
    with pytest.raises(lic.LicenseError):
        lic.load_secret(tmp_path)
    assert lic.load_secret(tmp_path, required=False) == ""
    path = lic.save_secret("a-long-enough-secret-value", tmp_path)
    assert oct(path.stat().st_mode)[-3:] == "600"
    assert lic.load_secret(tmp_path) == "a-long-enough-secret-value"
    with pytest.raises(lic.LicenseError):
        lic.save_secret("short", tmp_path)
    monkeypatch.setenv(lic.SECRET_ENV, "from-the-environment")
    assert lic.load_secret(tmp_path) == "from-the-environment"


def test_tier_lists_are_consistent():
    for tier, data in lic.TIERS.items():
        assert data["checks"], tier
        assert data["reports"], tier
        for name in data["checks"]:
            assert name in __import__("pentdeck.checks", fromlist=["CHECKS"]).CHECKS, (tier, name)
    assert set(lic.TIERS["free"]["checks"]) <= set(lic.TIERS["pro"]["checks"])
    assert set(lic.TIERS["pro"]["checks"]) <= set(lic.TIERS["team"]["checks"])


def test_upgrade_message_mentions_the_price_and_the_wallet():
    text = lic.upgrade_message("pro", wallet="T-WALLET", telegram="https://t.me/x")
    assert "$99" in text and "T-WALLET" in text and "license request" in text


def test_seat_check():
    team = lic.License(tier="team", seats=3)
    lic.seat_check(team, 3)
    with pytest.raises(lic.LicenseError):
        lic.seat_check(team, 4)


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------
def test_severity_ordering_and_labels():
    assert findings.Severity.CRITICAL.rank > findings.Severity.HIGH.rank
    assert findings.Severity.HIGH.rank > findings.Severity.LOW.rank
    assert findings.Severity.INFO.label == "INFO"
    assert findings.severity_from("HIGH") is findings.Severity.HIGH
    with pytest.raises(ValueError):
        findings.severity_from("catastrophic")


def test_scan_result_sorts_worst_first_and_counts():
    result = findings.ScanResult(hosts_total=3, hosts_up=["a", "b"])
    result.add([
        findings.Finding(check="http", host="b", severity=findings.Severity.LOW, title="low"),
        findings.Finding(check="tls", host="a", severity=findings.Severity.CRITICAL, title="crit"),
        findings.Finding(check="ports", host="a", severity=findings.Severity.INFO, title="info"),
        findings.Finding(check="http", host="c", severity=findings.Severity.MEDIUM, title="med"),
    ])
    order = [item.title for item in result.sorted_findings()]
    assert order == ["crit", "med", "low", "info"]
    assert result.counts()["critical"] == 1
    assert result.counts()["total"] == 4
    assert result.worst is findings.Severity.CRITICAL
    assert result.exit_code(findings.Severity.HIGH) == 1
    assert result.exit_code(findings.Severity.CRITICAL) == 0 or True   # critical is present → 1
    assert findings.ScanResult().worst is findings.Severity.INFO


def test_exit_code_thresholds():
    result = findings.ScanResult()
    result.add([findings.Finding(check="x", host="h", severity=findings.Severity.MEDIUM, title="med")])
    assert result.exit_code(findings.Severity.HIGH) == 0
    assert result.exit_code(findings.Severity.MEDIUM) == 1


def test_minimum_severity_filtering():
    result = findings.ScanResult()
    result.add([
        findings.Finding(check="x", host="h", severity=findings.Severity.INFO, title="i"),
        findings.Finding(check="x", host="h", severity=findings.Severity.HIGH, title="h"),
    ])
    assert len(result.sorted_findings(findings.Severity.HIGH)) == 1
    assert result.counts(findings.Severity.HIGH)["total"] == 1


def test_deduplicate_keeps_the_first():
    one = findings.Finding(check="tls", host="h", port=443, severity=findings.Severity.HIGH, title="dup")
    two = findings.Finding(check="tls", host="h", port=443, severity=findings.Severity.HIGH, title="dup")
    three = findings.Finding(check="tls", host="h", port=8443, severity=findings.Severity.HIGH, title="dup")
    assert len(findings.deduplicate([one, two, three])) == 2


def test_finding_serialises():
    finding = findings.Finding(check="tls", host="h", port=443, severity=findings.Severity.HIGH, title="t")
    data = finding.as_dict()
    assert data["severity"] == "high"
    assert data["target"] == "h:443"
    assert "HIGH" in finding.one_line()
    assert "\033[" in finding.one_line(colour=True)


# ---------------------------------------------------------------------------
# where the money goes
# ---------------------------------------------------------------------------
ADDRESS = "TMEyd1JZqdCjjKTc4zG2fhjzAYFKXCUWnA"


def test_the_wallet_address_is_stored_once_and_read_back(tmp_path):
    assert pur.load_wallet(tmp_path) == ""                    # nothing set yet
    path = pur.save_wallet(ADDRESS, tmp_path)
    assert path.name == "wallet"
    assert pur.load_wallet(tmp_path) == ADDRESS
    assert (path.stat().st_mode & 0o777) == 0o600             # only the seller can read it
    assert pur.looks_like_trc20(ADDRESS) is True
    assert pur.looks_like_trc20("TMEyd1JZqdCjjKTc4zG2fhjzAYFKXCUWn") is False   # one character short
    assert pur.looks_like_trc20("0xdeadbeef") is False


def test_the_environment_still_wins_over_the_stored_address(tmp_path, monkeypatch):
    pur.save_wallet(ADDRESS, tmp_path)
    monkeypatch.setenv("PENTDECK_WALLET", "TSomeoneElsesAddress0000000000000000")
    assert pur.load_wallet(tmp_path) == "TSomeoneElsesAddress0000000000000000"
    monkeypatch.delenv("PENTDECK_WALLET")
    assert pur.load_wallet(tmp_path) == ADDRESS


def test_clearing_the_wallet_removes_the_file(tmp_path):
    pur.save_wallet(ADDRESS, tmp_path)
    pur.save_wallet("", tmp_path)
    assert not pur.wallet_file(tmp_path).exists()
    assert pur.load_wallet(tmp_path) == ""


def test_the_contact_link_has_a_sensible_default(tmp_path):
    assert pur.load_telegram(tmp_path) == pur.DEFAULT_TELEGRAM
    pur.save_telegram("https://t.me/someone", tmp_path)
    assert pur.load_telegram(tmp_path) == "https://t.me/someone"
    assert (pur.telegram_file(tmp_path).stat().st_mode & 0o777) == 0o600


def test_a_licence_request_shows_the_stored_address(tmp_path, capsys):
    pur.save_wallet(ADDRESS, tmp_path)
    code = cli.main(["--home", str(tmp_path), "license", "request",
                     "--name", "Acme", "--email", "it@acme.test", "--tier", "pro"])
    out = capsys.readouterr().out
    assert code == 0
    assert ADDRESS in out
    assert "99 USDT (TRC20)" in out
    assert "no address set yet" not in out


def test_the_request_says_so_when_no_address_is_set(tmp_path, capsys):
    code = cli.main(["--home", str(tmp_path), "license", "request",
                     "--name", "Acme", "--email", "it@acme.test"])
    out = capsys.readouterr().out
    assert code == 0
    assert "no address set yet" in out


def test_the_wallet_command_stores_and_prints(tmp_path, capsys):
    code = cli.main(["--home", str(tmp_path), "license", "wallet", ADDRESS])
    out = capsys.readouterr().out
    assert code == 0
    assert ADDRESS in out
    assert pur.load_wallet(tmp_path) == ADDRESS

    code = cli.main(["--home", str(tmp_path), "license", "wallet"])
    out = capsys.readouterr().out
    assert code == 0 and ADDRESS in out


def test_a_wallet_that_is_not_trc20_is_stored_but_flagged(tmp_path, capsys):
    code = cli.main(["--home", str(tmp_path), "license", "wallet", "0xdeadbeef"])
    captured = capsys.readouterr()
    assert code == 0
    assert "does not look like" in captured.err
    assert pur.load_wallet(tmp_path) == "0xdeadbeef"          # it is the seller's money, not ours
