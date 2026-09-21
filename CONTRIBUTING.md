# Contributing to pentdeck

Thanks for looking. pentdeck is deliberately small and boring to maintain: a package with
**no required dependencies**, a test suite that runs offline in under a minute, and a
desktop dashboard behind an optional extra. Patches that keep it that way are easy to
accept.

## Ground rules

1. **The core stays dependency-free.** `pip install -e .` must work on a bare Python 3.9.
   PyQt6 is the only optional extra; anything else needs a conversation first.
2. **Python 3.9 syntax.** No `X | Y` type unions at runtime, no `match`, no `tomllib`.
   `from __future__ import annotations` is already at the top of every module for the
   annotations themselves.
3. **Nothing that leaves the machine at import time.** No network calls, no telemetry, no
   licence server. The only HTTP a scan makes is the HTTP the operator asked for, to
   targets they named.
4. **The rules live in the engine, not in the interface.** The scope check, the licence
   gate and the audit log are enforced in `engine.py` so that the CLI, the dashboard and
   anything else built later cannot disagree about them. Never gate something in the UI
   that the engine does not also enforce.
5. **Errors are findings, not tracebacks.** A host that does not answer is a result. A
   check that raises is caught, recorded and the scan carries on.
6. **Never commit a secret.** No wallet addresses in code (they belong in `~/.pentdeck/wallet`),
   no licence secrets, no bot tokens, no `PD1.…` tokens. The signing secret is generated
   per installation; if you ever see one in a diff, stop and say so in the issue.

## The layout

```
pentdeck/
  scope.py        targets, CIDR/range expansion, the authorization record, audit.jsonl
  license.py      signed offline tokens, tiers, machine binding
  checks.py       the checks and the registry that gates them by licence
  engine.py       one host at a time, one check at a time, in order
  findings.py     the finding model and the scan result
  certs.py        TLS reading, standard library only
  report.py       text / JSON / Markdown / self-contained HTML
  purchase.py     the buyer side and the seller's delivery
  seller.py       the order book and the order bot
  desktop/        the PyQt6 dashboard (optional extra)
  cli.py          the command line
```

## Testing

```bash
pip install -e ".[dev]"
pytest -q                          # ~35 s, no network
```

Everything is offline on purpose. The engine tests start their own HTTP, TLS and banner
servers on `127.0.0.1`; the dashboard tests run the real window under
`QT_QPA_PLATFORM=offscreen` and **skip themselves** when PyQt6 is missing — a bare
container is not a broken tool, and CI treats the two the same. The seller-bot tests
inject the two functions that would talk to Telegram, so a whole buying journey runs in
milliseconds without an account or any money.

Adding a check:

1. write it in `checks.py` as a function taking a `CheckContext` and returning findings;
2. register it in `CHECKS` with a stage, a description and whether it is intrusive;
3. decide which licence tiers include it (`license.py`, `TIERS`);
4. test it against a server your test starts, including the case where the service is
   absent — a check that is silent when there is nothing to find is a check that works;
5. write the remediation text as an instruction a sysadmin can follow without reading
   your code.

## The desktop extra

```bash
pip install -e ".[desktop]"
pentdeck gui
```

The dashboard must never grow its own copy of a rule. It calls `engine.run_scan`, reads
the same `scope.json`, the same `license.json` and the same `audit.jsonl`. If you need
something the engine does not expose, add it to the engine.

**Nothing in `desktop/safety.py` may write to `sys.stdout` or `sys.stderr`.** A windowed
build starts with both set to `None`, and an unexpected write there kills the app before
it can draw a window — a bug that shipped once in a sibling project. Use the log file.

## Releases

A release is a tag. `.github/workflows/release.yml` then:

1. runs the test suite on Windows,
2. builds both executables with PyInstaller,
3. smoke-tests the CLI from a shell **and the dashboard with `Start-Process`** — no
   console, the way a customer launches it — and fails the release if the log never says
   `window shown`,
4. attaches the executables to the release and announces it on Telegram.

Bump `pentdeck/__init__.py` and `pyproject.toml` in the same commit as the tag.

## Reporting something

Issues are welcome, including "this check reported something that is not a real problem"
— a noisy scanner is a broken scanner. Please say what you scanned (never a client's real
addresses) and what you expected instead.
