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
    cli.py        the command line
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
