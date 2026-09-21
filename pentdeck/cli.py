"""The command line.

    pentdeck scope init --name "Acme HQ" --add 192.168.1.0/28
    pentdeck authorize --operator "S. Shaghoulian" --reference "contract 2026-114"
    pentdeck scan
    pentdeck scan --html report.html --md report.md --json > report.json
    pentdeck license status
    pentdeck license request --name "..." --email "..." --tier pro

Nothing here imports Qt: the tool is usable over SSH on the client's jump host,
which is where a pentester usually ends up working.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from typing import List, Optional, Sequence

from . import __version__
from .checks import CHECKS, ORDER, check_titles
from .engine import ScanOptions, plan_checks, run_scan
from .findings import ScanResult, Severity, severity_from
from .license import (TIERS, LicenseError, current_license, inspect_token, install_token,
                      issue_token, load_secret, upgrade_message)
from .report import format_html, format_json, format_markdown, format_text
from .scope import DEFAULT_PORTS, AuditLog, Scope, ScopeError, require_authorization

#: Where the money goes by default: `pentdeck license wallet <address>` writes it to
#: the state directory once. PENTDECK_WALLET still overrides it. Use a
#: wallet you keep for sales, not the one you publish for tips.
DEFAULT_TELEGRAM = "https://t.me/luyavaai"


def default_home() -> pathlib.Path:
    override = os.environ.get("PENTDECK_HOME")
    return pathlib.Path(override) if override else pathlib.Path.home() / ".pentdeck"


def parse_ports(text: str) -> List[int]:
    """'22,80,443' or '1-1024' or a mix."""
    ports: List[int] = []
    for piece in str(text).split(","):
        piece = piece.strip()
        if not piece:
            continue
        if "-" in piece:
            start_text, _, end_text = piece.partition("-")
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise ValueError(f"{piece!r} is not a port range") from exc
            if not 1 <= start <= end <= 65535:
                raise ValueError(f"{piece!r} is outside 1-65535")
            ports.extend(range(start, end + 1))
        else:
            port = int(piece)
            if not 1 <= port <= 65535:
                raise ValueError(f"{port} is outside 1-65535")
            ports.append(port)
    unique = sorted(set(ports))
    if not unique:
        raise ValueError("no ports given")
    return unique


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pentdeck",
        description="A pentest workbench: scan an authorised network, read the findings, "
                    "hand the client a report.",
        epilog=(
            "examples:\n"
            "  pentdeck scope init --name \"Acme HQ\" --add 192.168.1.0/28\n"
            "  pentdeck authorize --operator \"Your Name\" --reference \"contract 2026-114\"\n"
            "  pentdeck scan --html report.html\n"
            "  pentdeck tools\n"
            "  pentdeck license request --name \"Acme\" --email it@acme.test --tier pro\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--home", metavar="DIR", help=f"state directory (default: {default_home()})")
    parser.add_argument("--version", action="version", version=f"pentdeck {__version__}")
    sub = parser.add_subparsers(dest="command")

    # ── scope ────────────────────────────────────────────────────────────────
    scope_cmd = sub.add_parser("scope", help="what may be scanned")
    scope_sub = scope_cmd.add_subparsers(dest="scope_command")
    scope_init = scope_sub.add_parser("init", help="create the scope file")
    scope_init.add_argument("--name", default="default")
    scope_init.add_argument("--add", action="append", default=[], metavar="TARGET",
                            help="a host, CIDR or range (repeatable)")
    scope_init.add_argument("--allow-public", action="store_true",
                            help="allow public addresses (only with real authority)")
    scope_init.add_argument("--force", action="store_true", help="overwrite an existing scope")
    scope_sub.add_parser("show", help="print the scope")
    scope_add = scope_sub.add_parser("add", help="add a target")
    scope_add.add_argument("target")
    scope_remove = scope_sub.add_parser("remove", help="remove a target")
    scope_remove.add_argument("target")
    scope_deny = scope_sub.add_parser("deny", help="never touch this target")
    scope_deny.add_argument("target")
    scope_public = scope_sub.add_parser("allow-public", help="allow or forbid public addresses")
    scope_public.add_argument("value", choices=("on", "off"))

    # ── authorize ────────────────────────────────────────────────────────────
    auth = sub.add_parser("authorize", help="record who authorized this assessment")
    auth.add_argument("--operator", required=True)
    auth.add_argument("--reference", required=True,
                      help="contract number, approval e-mail subject, or ticket id")
    auth.add_argument("--note", default="")

    # ── scan ─────────────────────────────────────────────────────────────────
    scan = sub.add_parser("scan", help="run the assessment")
    scan.add_argument("--ports", help="port list or range (default: the usual suspects)")
    scan.add_argument("--top", action="store_true", help="only the twelve most common ports")
    scan.add_argument("--intrusive", action="store_true", help="enable checks that touch more")
    scan.add_argument("--only", action="append", default=[], choices=sorted(CHECKS))
    scan.add_argument("--skip", action="append", default=[], choices=sorted(CHECKS))
    scan.add_argument("--timeout", type=float, default=5.0)
    scan.add_argument("--host-workers", type=int, default=8)
    scan.add_argument("--port-workers", type=int, default=64)
    scan.add_argument("--host-delay", type=float, default=0.0)
    scan.add_argument("--operator", default="", help="authorization for this run only")
    scan.add_argument("--reference", default="")
    scan.add_argument("--json", action="store_true", help="print the JSON report")
    scan.add_argument("--md", metavar="FILE")
    scan.add_argument("--html", metavar="FILE")
    scan.add_argument("--min-severity", default="info")
    scan.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "info", "never"])
    scan.add_argument("--quiet", action="store_true", help="only write files")
    scan.add_argument("--no-color", action="store_true")

    # ── tools / audit ────────────────────────────────────────────────────────
    sub.add_parser("tools", help="list the checks and which licence unlocks them")
    audit = sub.add_parser("audit", help="show the audit trail")
    audit.add_argument("-n", type=int, default=20)

    # ── licence ──────────────────────────────────────────────────────────────
    lic = sub.add_parser("license", help="licence status, purchase and installation")
    lic_sub = lic.add_subparsers(dest="license_command")
    lic_sub.add_parser("status", help="what this installation is allowed to do")
    lic_install = lic_sub.add_parser("install", help="install a licence token")
    lic_install.add_argument("token", help="the PD1.… token you were sent")
    lic_inspect = lic_sub.add_parser("inspect", help="read a token without installing it")
    lic_inspect.add_argument("token")
    lic_issue = lic_sub.add_parser("issue", help="vendor side: create a token")
    lic_issue.add_argument("--customer", required=True)
    lic_issue.add_argument("--tier", default="pro", choices=sorted(TIERS))
    lic_issue.add_argument("--days", type=int, default=3650, help="0 for a licence that never expires")
    lic_issue.add_argument("--order", default="")
    lic_issue.add_argument("--machine", default="", help="bind to a machine id (see `pentdeck machine`)")
    lic_issue.add_argument("--seats", type=int, default=1)
    lic_req = lic_sub.add_parser("request", help="buyer side: ask for a licence")
    lic_req.add_argument("--name", required=True)
    lic_req.add_argument("--email", required=True)
    lic_req.add_argument("--tier", default="pro", choices=["pro", "team"])
    lic_req.add_argument("--note", default="")
    lic_req.add_argument("--send", action="store_true",
                         help="actually send the request to the Telegram bot (needs PENTDECK_BUY_BOT_TOKEN)")
    lic_up = lic_sub.add_parser("upgrade", help="what the paid version adds")
    lic_up.add_argument("--tier", default="pro", choices=["pro", "team"])
    lic_wallet = lic_sub.add_parser("wallet", help="the address buyers pay to")
    lic_wallet.add_argument("address", nargs="?",
                            help="the wallet address to store; omit to print the current one")
    lic_wallet.add_argument("--telegram", default="",
                            help="also store the contact link buyers should use")
    sub.add_parser("machine", help="print this machine's id, for a bound licence")

    # ── seller ───────────────────────────────────────────────────────────────
    seller = sub.add_parser("seller", help="run the order bot, or drive orders by hand")
    seller_sub = seller.add_subparsers(dest="seller_command")
    seller_run = seller_sub.add_parser("run", help="long-poll the bot and answer buyers")
    seller_run.add_argument("--once", action="store_true", help="one pass, then exit")
    seller_run.add_argument("--poll-timeout", type=int, default=25,
                            help="seconds Telegram may hold the connection open")
    seller_orders = seller_sub.add_parser("orders", help="list orders")
    seller_orders.add_argument("--all", action="store_true", help="include delivered and cancelled")
    seller_confirm = seller_sub.add_parser("confirm", help="the payment arrived: issue and deliver")
    seller_confirm.add_argument("code")
    seller_confirm.add_argument("--txid", default="")
    seller_confirm.add_argument("--machine", default="", help="bind the licence to a machine id")
    seller_confirm.add_argument("--send", action="store_true",
                                help="deliver it to the buyer's chat (needs the bot token)")
    seller_confirm.add_argument("--days", type=int, default=3650)
    seller_show = seller_sub.add_parser("show", help="everything about one order")
    seller_show.add_argument("code")
    seller_sub.add_parser("stats", help="orders, deliveries and money")
    seller_sub.add_parser("demo", help="run the whole buying journey offline, on this "
                                       "machine, with no bot and no money")
    seller_sub.add_parser(
        "whoami",
        help="list the chats that have written to the bot, so you can copy your own id",
    )

    # ── desktop ──────────────────────────────────────────────────────────────
    gui = sub.add_parser("gui", help="open the desktop dashboard (needs PyQt6)")
    gui.add_argument("--scan", action="store_true",
                     help="open on the Scan page instead of the overview")

    return parser


# ---------------------------------------------------------------------------
# command handlers
# ---------------------------------------------------------------------------
def _scope_or_die(args: argparse.Namespace, home: pathlib.Path, create: bool = True) -> Scope:
    try:
        return Scope.load(home)
    except ScopeError as exc:
        if not create:
            raise
        raise ScopeError(f"{exc}\n\nstart with:\n  pentdeck scope init --name \"Client\" --add 192.168.1.0/24") from exc


def cmd_scope(args: argparse.Namespace, home: pathlib.Path) -> int:
    script = args.scope_command or "show"
    if script == "init":
        if args.force or not Scope.path(home).exists():
            scope = Scope(name=args.name, allow_public=bool(args.allow_public))
            for entry in args.add or ["127.0.0.1"]:
                scope.add(entry)
            path = scope.save(home)
            print(f"scope written to {path}")
            if not args.add:
                print("note: no --add was given, so 127.0.0.1 was used as a placeholder. "
                      "Change it with `pentdeck scope add`.")
        else:
            print(f"{Scope.path(home)} already exists — use --force to overwrite", file=sys.stderr)
            return 2
        print(Scope.load(home).summary())
        return 0

    scope = Scope.load(home)
    if script == "show":
        print(scope.summary())
        return 0
    if script == "add":
        scope.add(args.target)
    elif script == "remove":
        if not scope.remove(args.target):
            print(f"{args.target!r} was not in the scope", file=sys.stderr)
            return 1
    elif script == "deny":
        scope.deny.append(args.target)
    elif script == "allow-public":
        scope.allow_public = args.value == "on"
    scope.save(home)
    print(scope.summary())
    return 0


def cmd_authorize(args: argparse.Namespace, home: pathlib.Path) -> int:
    from .scope import Authorization

    scope = Scope.load(home)
    scope.authorization = Authorization(operator=args.operator, reference=args.reference, note=args.note)
    scope.save(home)
    AuditLog(home).append("authorization", operator=args.operator, reference=args.reference)
    print("authorization recorded:")
    print(f"  {scope.authorization.summary()}")
    return 0


def cmd_tools(args: argparse.Namespace, home: pathlib.Path) -> int:
    license_ = current_license(home)
    print(f"pentdeck {__version__} — checks")
    print(f"{'check':<20} {'stage':<6} {'licence':<8} intrusive  what it does")
    for name in ORDER:
        check = CHECKS[name]
        tiers = [tier for tier, data in TIERS.items() if name in data["checks"]]
        cheapest = "free" if "free" in tiers else ("pro" if "pro" in tiers else "team")
        allowed = "yes" if license_.allows_check(name) else "no"
        flag = "yes" if check.intrusive else "-"
        print(f"{name:<20} {check.stage:<6} {cheapest:<8} {flag:<10} {check.description}  [{allowed} here]")
    print()
    print(license_.summary())
    if not license_.is_paid:
        print()
        print(upgrade_message("pro", _wallet(home), _telegram(home)))
    return 0


def _wallet(home: pathlib.Path) -> str:
    from .purchase import load_wallet

    return load_wallet(home)


def _telegram(home: pathlib.Path) -> str:
    from .purchase import load_telegram

    return load_telegram(home)


def cmd_scan(args: argparse.Namespace, home: pathlib.Path) -> int:
    scope = Scope.load(home)
    license_ = current_license(home)
    try:
        authorization = require_authorization(scope, args.operator or None, args.reference or None)
        if args.operator or args.reference:
            scope.authorization = authorization              # keep the record for next time
            scope.save(home)
    except ScopeError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    if args.ports:
        ports = parse_ports(args.ports)
    elif args.top:
        from .scope import TOP_PORTS
        ports = list(TOP_PORTS)
    else:
        ports = list(DEFAULT_PORTS)

    options = ScanOptions(
        ports=ports,
        intrusive=bool(args.intrusive),
        timeout=args.timeout,
        host_workers=max(1, args.host_workers),
        port_workers=max(1, args.port_workers),
        host_delay=max(0.0, args.host_delay),
        only=tuple(args.only),
        skip=tuple(args.skip),
        operator=authorization.operator,
        reference=authorization.reference,
    )
    checks, skipped = plan_checks(license_, options)
    if skipped and not args.json and not args.quiet:
        print("checks that will not run:", file=sys.stderr)
        for name, reason in skipped:
            print(f"  {name:<20} {reason}", file=sys.stderr)

    print(f"scanning {len(scope.hosts())} host(s) in scope {scope.name!r} "
          f"with {len(checks)} check(s), {len(ports)} port(s)...", file=sys.stderr)
    try:
        result = run_scan(scope, license_, options, home)
    except ScopeError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    minimum = severity_from(args.min_severity)
    if args.json:
        print(format_json(result))
    elif not args.quiet:
        colour = (not args.no_color) and sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        print(format_text(result, colour=colour, minimum=minimum))

    for kind, path in (("markdown", args.md), ("html", args.html)):
        if not path:
            continue
        if not license_.allows_report(kind):
            print(f"refused: the {kind} report needs a paid licence — "
                  f"run `pentdeck license upgrade`", file=sys.stderr)
            continue
        writer = format_markdown if kind == "markdown" else format_html
        pathlib.Path(path).write_text(writer(result, minimum), encoding="utf-8")
        print(f"{kind} report: {path}", file=sys.stderr)

    target = args.fail_on
    if target == "never":
        return 0
    threshold = severity_from(target)
    return result.exit_code(threshold)


def cmd_audit(args: argparse.Namespace, home: pathlib.Path) -> int:
    log = AuditLog(home)
    records = log.tail(args.n)
    if not records:
        print(f"nothing recorded yet ({log.path})")
        return 0
    for record in records:
        when = str(record.get("time", ""))[:19]
        event = str(record.get("event", ""))
        rest = {key: value for key, value in record.items() if key not in ("time", "event")}
        print(f"{when}  {event:<14} {json.dumps(rest, ensure_ascii=False)}")
    return 0


def cmd_license(args: argparse.Namespace, home: pathlib.Path) -> int:
    script = args.license_command or "status"
    license_ = current_license(home)

    if script == "status":
        print(license_.summary())
        print()
        if not license_.is_paid:
            print(upgrade_message("pro", _wallet(home), _telegram(home)))
        return 0

    if script == "install":
        try:
            license_ = install_token(args.token, home)
        except LicenseError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print("licence installed:")
        print(license_.summary())
        return 0

    if script == "inspect":
        try:
            payload = inspect_token(args.token)
        except LicenseError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(payload, indent=2))
        print("\n(NOT verified — use `license install` to check the signature)")
        return 0

    if script == "issue":
        try:
            secret = load_secret(home)
            token = issue_token(
                secret,
                args.customer,
                tier=args.tier,
                days=args.days or None,
                order=args.order,
                machine=args.machine,
                seats=args.seats,
            )
        except LicenseError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(token)
        print("\nSend that line to the customer. It is safe to e-mail: it only unlocks "
              "the tools, and it is signed so it cannot be edited.", file=sys.stderr)
        return 0

    if script == "wallet":
        from .purchase import load_telegram, load_wallet, looks_like_trc20, save_wallet, save_telegram

        if args.address:
            path = save_wallet(args.address, home)
            print(f"wallet stored in {path} (mode 0600)")
            if not looks_like_trc20(args.address):
                print("note: that does not look like a USDT (TRC20) address — they start "
                      "with T and are 34 characters. Stored anyway: it is your money.",
                      file=sys.stderr)
            if args.telegram:
                save_telegram(args.telegram, home)
        current = load_wallet(home)
        print(f"wallet   : {current or 'not set yet — run `pentdeck license wallet <address>`'}")
        print(f"contact  : {load_telegram(home)}")
        return 0

    if script == "request":
        from .purchase import load_telegram, load_wallet

        order = f"PD-{os.urandom(2).hex().upper()}"
        wallet = load_wallet(home)
        lines = [
            f"order       : {order}",
            f"name        : {args.name}",
            f"email       : {args.email}",
            f"tier        : {args.tier} (${TIERS[args.tier]['price_usd']})",
            f"amount      : {TIERS[args.tier]['price_usd']} USDT (TRC20)",
            f"wallet      : {wallet or 'no address set yet — run `pentdeck license wallet <address>`'}",
            f"reference   : put {order} in the payment memo",
            "",
            "Send exactly that amount, then send the transaction id (txid) to the Telegram "
            "contact below — the licence token comes back in the same chat.",
            "",
            f"contact     : {load_telegram(home)}",
        ]
        if args.note:
            lines.append(f"note        : {args.note}")
        print("\n".join(lines))

        if args.send:
            token = os.environ.get("PENTDECK_BUY_BOT_TOKEN", "")
            chat = os.environ.get("PENTDECK_BUY_CHAT_ID", "")
            if not token or not chat:
                print("\n--send needs PENTDECK_BUY_BOT_TOKEN and PENTDECK_BUY_CHAT_ID", file=sys.stderr)
                return 2
            from .purchase import send_order

            ok, detail = send_order(
                "\n".join([f"🛒 new licence request", f"order: {order}", f"name: {args.name}",
                           f"email: {args.email}", f"tier: {args.tier}", f"note: {args.note}"]),
                token, chat,
            )
            print(("sent to the seller: " if ok else "could not send: ") + detail, file=sys.stderr)
            return 0 if ok else 1
        return 0

    if script == "upgrade":
        print(upgrade_message(args.tier, _wallet(home), _telegram(home)))
        return 0

    return 0


def cmd_seller(args: argparse.Namespace, home: pathlib.Path) -> int:
    from .purchase import load_telegram, load_wallet
    from .seller import (OrderBook, confirm_by_hand, serve, seller_ids)

    script = args.seller_command or "orders"
    book = OrderBook.load(home)

    if script == "run":
        from .purchase import load_telegram as _tg, load_wallet as _w

        token = os.environ.get("PENTDECK_BUY_BOT_TOKEN", "")
        if not token:
            print("set PENTDECK_BUY_BOT_TOKEN first — the bot the buyers message", file=sys.stderr)
            return 2
        if not seller_ids():
            print("set PENTDECK_BUY_CHAT_ID to your own chat id, or nobody can confirm an "
                  "order (and every buyer would be treated as the seller)", file=sys.stderr)
            return 2
        if not _w(home):
            print("note: no wallet address stored — buyers will be told the seller will send "
                  "it. Run `pentdeck license wallet <address>`.", file=sys.stderr)
        try:
            return serve(token, home, wallet=_w(home), telegram=_tg(home),
                         poll_timeout=args.poll_timeout, once=args.once)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if script == "orders":
        shown = book.orders if args.all else book.pending()
        if not shown:
            print("nothing pending" if not args.all else "no orders yet")
            return 0
        width = max(len(order.code) for order in shown)
        for order in shown:
            print(f"{order.code:<{width}}  {order.tier:<5} ${order.price:<4} "
                  f"{order.status:<9} {order.created[:19]}  {order.name} {order.email}"
                  + (f"  txid {order.txid[:24]}" if order.txid else ""))
        return 0

    if script == "show":
        order = book.get(args.code)
        if order is None:
            print(f"no order {args.code.upper()}", file=sys.stderr)
            return 1
        print(json.dumps(order.as_dict(), indent=2, ensure_ascii=False))
        return 0

    if script == "demo":
        from .seller import run_demo

        return run_demo()

    if script == "whoami":
        from .seller import recent_chats, seller_ids

        token = os.environ.get("PENTDECK_BUY_BOT_TOKEN", "")
        if not token:
            print("set PENTDECK_BUY_BOT_TOKEN first — the bot the buyers message", file=sys.stderr)
            return 2
        chats = recent_chats(token)
        if not chats:
            print("no recent messages. Open Telegram, send your bot any message "
                  "(for example /start), then run this again.", file=sys.stderr)
            return 1
        known = set(seller_ids())
        print(f"{'chat id':<16} {'you?':<5} name / username")
        for chat in chats:
            mark = "yes" if chat["chat_id"] in known else ""
            who = chat["name"] + (f" @{chat['username']}" if chat["username"] else "")
            print(f"{chat['chat_id']:<16} {mark:<5} {who}")
        print("\nthe id marked 'yes' is the one already configured. To use another:\n"
              "  PENTDECK_BUY_CHAT_ID=<id>  (Windows: setx PENTDECK_BUY_CHAT_ID <id>)")
        return 0

    if script == "stats":
        stats = book.stats()
        print(f"orders    : {stats['orders']}")
        print(f"pending   : {stats['pending']}")
        print(f"delivered : {stats['delivered']}")
        print(f"cancelled : {stats['cancelled']}")
        print(f"collected : ${stats['revenue_usd']} (delivered orders only)")
        return 0

    if script == "confirm":
        ok, message = confirm_by_hand(args.code, home, txid=args.txid, machine=args.machine,
                                      send=args.send)
        print(message)
        if not ok:
            print("(nothing arrived from the buyer? the token above is issued but not "
                  "delivered — send it by hand, or fix the chat id and try again)",
                  file=sys.stderr)
            return 1
        return 0

    print("usage: pentdeck seller {run|orders|show|confirm|stats}", file=sys.stderr)
    return 2


def cmd_machine(args: argparse.Namespace, home: pathlib.Path) -> int:
    from .license import machine_id

    print(machine_id())
    print("Give this value to the vendor for `license issue --machine <id>` if you want "
          "the licence bound to this machine.")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    home = pathlib.Path(args.home) if getattr(args, "home", None) else default_home()
    home.mkdir(parents=True, exist_ok=True)

    command = getattr(args, "command", None)
    try:
        if command == "scope":
            return cmd_scope(args, home)
        if command == "authorize":
            return cmd_authorize(args, home)
        if command == "scan":
            return cmd_scan(args, home)
        if command == "tools":
            return cmd_tools(args, home)
        if command == "audit":
            return cmd_audit(args, home)
        if command == "license":
            return cmd_license(args, home)
        if command == "machine":
            return cmd_machine(args, home)
        if command == "seller":
            return cmd_seller(args, home)
        if command == "gui":
            try:
                from .desktop.app import run_gui
            except ImportError as exc:
                print("the dashboard needs PyQt6 — install it with: "
                      'pip install "pentdeck[desktop]"', file=sys.stderr)
                print(f"({exc})", file=sys.stderr)
                return 2
            return run_gui(home=str(home), start_scan=bool(getattr(args, "scan", False)))
    except ScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except LicenseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    parser.print_help()
    print("\nNo command given. A reasonable first three:\n"
          "  pentdeck scope init --name \"Client\" --add 192.168.1.0/24\n"
          "  pentdeck authorize --operator \"Your Name\" --reference \"contract 2026-114\"\n"
          "  pentdeck scan --html report.html")
    return 0


if __name__ == "__main__":                                    # pragma: no cover
    sys.exit(main())
