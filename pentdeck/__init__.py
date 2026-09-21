"""pentdeck — a pentest workbench for authorised internal assessments.

Modules:
    scope.py      targets, the authorization record, the audit trail
    license.py    signed offline licences, tiers, and what each one unlocks
    findings.py   the finding model: severity, evidence, remediation
    certs.py      TLS certificate reading (standard library only)
    checks.py     the checks, and the registry that gates them by licence
    engine.py     the scan engine
    report.py     text, JSON, Markdown and HTML reports
    purchase.py   licence requests and delivery over a Telegram bot
    seller.py     the seller's side: the order book and the order bot
    cli.py        the command line
    desktop/      the PyQt6 dashboard (optional extra)
"""

__version__ = "0.1.1"
__all__ = ["__version__"]
