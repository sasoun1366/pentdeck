"""The seller side: a bot that takes orders and issues licences.

There is no payment gateway here, and this module is not pretending to have one. What it
automates is the bookkeeping and the messaging:

* a buyer sends the request the app produced → an order is recorded against *their* chat,
  and the bot replies with the address, the amount and the order code;
* the buyer sends a transaction id → the order is marked as claimed and the seller is
  told to check it;
* the seller confirms → the signed token is issued and delivered to the buyer's chat.

**The seller's confirmation is the only thing that releases a licence.** A bot cannot
verify a TRC20 transfer without a blockchain API key, and a bitcoin-style "trust the
text the buyer pasted" would either ship free licences or annoy a paying customer. So the
human checks the payment — that takes ten seconds in a wallet app — and the machine does
everything else.

Only the seller's own chat may run commands (`PENTDECK_BUY_CHAT_ID`, plus
`PENTDECK_SELLER_IDS` for a second device). A buyer can create an order, report a payment
and ask questions; nothing else.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import os
import pathlib
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .license import LicenseError, TIERS, issue_token
from .purchase import (collect_updates, load_telegram, load_wallet, order_code,
                       parse_order_message, send_license, send_order)

ORDER_FILENAME = "orders.json"

#: Paid → the money is with the seller and nobody has said so yet. Claimed → the buyer
#: says they sent it. Delivered → the token is in their chat.
STATUS_NEW = "new"
STATUS_CLAIMED = "claimed"
STATUS_DELIVERED = "delivered"
STATUS_CANCELLED = "cancelled"

SELLER_IDS_ENV = "PENTDECK_SELLER_IDS"

HELP = """pentdeck seller bot

Buyers
  • send the request that `pentdeck license request` writes → they get the address,
    the amount and their order code back, and you get told
  • send a transaction id → the order is marked as claimed

You (this chat only)
  /orders                 pending orders, oldest first
  /show PD-XXXX           everything about one order
  /confirm PD-XXXX [txid] the payment arrived — issues the licence and delivers it
  /issue PD-XXXX [--days 3650] [--machine ID] [--seats N]
                          re-issue by hand (a lost token, a new machine)
  /cancel PD-XXXX [why]   close an order
  /stats                  how many orders, how much money
  /help                   this text
"""


# ---------------------------------------------------------------------------
# the order book
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class Order:
    """One sale, from the first message to the delivered token."""

    code: str
    name: str = ""
    email: str = ""
    tier: str = "pro"
    chat_id: str = ""
    username: str = ""
    note: str = ""
    machine: str = ""
    created: str = ""
    status: str = STATUS_NEW
    txid: str = ""
    claimed_at: str = ""
    delivered_at: str = ""
    token: str = ""

    @property
    def price(self) -> int:
        return int(TIERS.get(self.tier, TIERS["pro"])["price_usd"])

    @property
    def label(self) -> str:
        return str(TIERS.get(self.tier, TIERS["pro"])["label"])

    def one_line(self) -> str:
        bits = [f"{self.code}", f"{self.tier} ${self.price}", self.status]
        if self.name:
            bits.append(self.name)
        if self.email:
            bits.append(f"<{self.email}>")
        if self.txid:
            bits.append(f"txid {self.txid[:16]}{'…' if len(self.txid) > 16 else ''}")
        return " · ".join(bits)

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class OrderBook:
    """Orders on disk, mode 0600, next to the wallet and the licence secret."""

    def __init__(self, home: Optional[pathlib.Path] = None, orders: Optional[List[Order]] = None,
                 offset: int = 0) -> None:
        self.home = pathlib.Path(home) if home else pathlib.Path.home() / ".pentdeck"
        self.orders: List[Order] = orders or []
        #: The last Telegram update id already handled, so a restart does not
        #: re-answer old messages (or deliver a second licence).
        self.offset = offset

    # ── the file ─────────────────────────────────────────────────────────────
    @property
    def path(self) -> pathlib.Path:
        return self.home / ORDER_FILENAME

    @classmethod
    def load(cls, home: Optional[pathlib.Path] = None) -> "OrderBook":
        book = cls(home)
        try:
            raw = json.loads(book.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return book
        book.offset = int(raw.get("offset") or 0)
        for item in raw.get("orders") or []:
            known = {field.name for field in dataclasses.fields(Order)}
            book.orders.append(Order(**{key: value for key, value in item.items() if key in known}))
        return book

    def save(self) -> pathlib.Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "offset": self.offset,
            "updated": _now(),
            "orders": [order.as_dict() for order in self.orders],
        }
        temporary = self.path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)
        return self.path

    # ── the orders ───────────────────────────────────────────────────────────
    def add(self, order: Order) -> Order:
        if not order.code:
            order.code = order_code()
        if not order.created:
            order.created = _now()
        self.orders.append(order)
        return order

    def get(self, code: str) -> Optional[Order]:
        wanted = (code or "").strip().upper()
        for order in self.orders:
            if order.code.upper() == wanted:
                return order
        return None

    def by_chat(self, chat_id: str) -> List[Order]:
        return [order for order in self.orders if order.chat_id == str(chat_id)]

    def pending(self) -> List[Order]:
        return [order for order in self.orders if order.status in (STATUS_NEW, STATUS_CLAIMED)]

    def open_for_chat(self, chat_id: str) -> Optional[Order]:
        """The newest order from this chat that is not finished yet."""
        for order in reversed(self.by_chat(chat_id)):
            if order.status in (STATUS_NEW, STATUS_CLAIMED):
                return order
        return None

    def stats(self) -> Dict[str, Any]:
        delivered = [order for order in self.orders if order.status == STATUS_DELIVERED]
        return {
            "orders": len(self.orders),
            "pending": len(self.pending()),
            "delivered": len(delivered),
            "revenue_usd": sum(order.price for order in delivered),
            "cancelled": len([order for order in self.orders if order.status == STATUS_CANCELLED]),
        }


# ---------------------------------------------------------------------------
# what a message means
# ---------------------------------------------------------------------------
def seller_ids(explicit: Optional[Iterable[str]] = None) -> List[str]:
    """Who may run commands. The seller's own chat, plus anything added by hand."""
    ids = {str(item).strip() for item in (explicit or []) if str(item).strip()}
    for source in (os.environ.get("PENTDECK_BUY_CHAT_ID", ""), os.environ.get(SELLER_IDS_ENV, "")):
        ids.update(part.strip() for part in source.split(",") if part.strip())
    return sorted(ids)


def is_seller(chat_id: str, allowed: Optional[Iterable[str]] = None) -> bool:
    return str(chat_id) in set(seller_ids(allowed))


#: A transaction hash. TRON hashes are 64 hex characters; an Ethereum-style `0x`
#: prefix is accepted as well, because a buyer may paste either one.
_TXID = re.compile(r"^(0x)?[0-9a-fA-F]{32,80}$")


def looks_like_txid(text: str) -> bool:
    return bool(_TXID.match((text or "").strip()))


def parse_machine(text: str) -> str:
    """Read ``machine: ab12cd34ef56`` out of a request, or the empty string."""
    for line in (text or "").splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() in ("machine", "machine id", "machine-id"):
            return value.strip()
    return ""


def build_payment_reply(order: Order, wallet: str, telegram: str = "") -> str:
    """What the buyer gets back: everything they need, in the order they need it."""
    lines = [
        f"🛒 pentdeck — order {order.code}",
        "",
        f"tier    : {order.label} (${order.price})",
        f"amount  : {order.price} USDT (TRC20)",
        f"wallet  : {wallet or '(the seller will send the address)'}",
        f"memo    : {order.code}",
        "",
        "Pay exactly that amount, then reply here with the transaction id (txid) — "
        "a long hex string. The licence token comes back in this chat.",
    ]
    if telegram:
        lines += ["", f"questions: {telegram}"]
    return "\n".join(lines)


class Actions:
    """Everything a message caused: replies to send, and what to tell the seller."""

    def __init__(self) -> None:
        self.sent: List[Tuple[str, str]] = []          # (chat_id, text)
        self.notes: List[str] = []                     # what happened, for the log

    def reply(self, chat_id: str, text: str) -> None:
        self.sent.append((str(chat_id), text))

    def note(self, text: str) -> None:
        self.notes.append(text)


def handle_message(message: Dict[str, Any], book: OrderBook, *, wallet: str = "",
                   telegram: str = "", secret: str = "", allowed: Optional[Iterable[str]] = None,
                   sender: Optional[Callable[[str, str], Tuple[bool, str]]] = None,
                   deliver: Optional[Callable[[str, str], Tuple[bool, str]]] = None,
                   now: Optional[str] = None) -> Actions:
    """Handle one incoming message. Pure bookkeeping: sending is injected.

    ``sender`` posts a plain reply; ``deliver`` posts a licence. Both default to the real
    Telegram API, which is why every test injects a fake and nothing touches the network.
    """
    actions = Actions()
    chat_id = str(message.get("chat_id", ""))
    text = str(message.get("text") or "").strip()
    stamp = now or _now()
    post = sender or (lambda target, body: send_order(body, _bot_token(), target))
    hand_over = deliver or (lambda target, token: send_license(token, _bot_token(), target))

    # ── the seller's own chat ────────────────────────────────────────────────
    if is_seller(chat_id, allowed):
        _handle_seller_command(text, book, actions, stamp, post, hand_over, chat_id)
        return actions

    # ── a buyer ──────────────────────────────────────────────────────────────
    if text.startswith("/"):
        actions.reply(chat_id, "This bot takes pentdeck licence orders. Send the request "
                               "that `pentdeck license request` writes, and it will answer "
                               "with the address and the amount.")
        actions.note(f"unknown command from {chat_id}: {text.split()[0]}")
        return actions

    fields = parse_order_message(text)
    if fields:
        tier = str(fields.get("tier", "pro")).split()[0].strip().lower()
        if tier not in TIERS or tier == "free":
            actions.reply(chat_id, f"'{tier}' is not a tier I sell — the paid ones are "
                                   f"{' and '.join(name for name in TIERS if name != 'free')}.")
            return actions
        order = book.open_for_chat(chat_id)
        if order is None:
            order = book.add(Order(
                code=str(fields.get("order") or "").strip() or order_code(),
                name=str(fields.get("name", "")).strip(),
                email=str(fields.get("email", "")).strip(),
                tier=tier,
                chat_id=chat_id,
                username=str(message.get("username", "")),
                note=str(fields.get("note", "")).strip(),
                machine=parse_machine(text),
            ))
            actions.note(f"new order {order.code} — {order.tier} from {chat_id} ({order.name})")
        else:
            actions.note(f"order {order.code} restated by {chat_id}")
        if wallet:
            actions.reply(chat_id, build_payment_reply(order, wallet, telegram))
        actions.reply(_seller_target(allowed), f"🛒 order {order.code}\n{order.one_line()}")
        return actions

    if looks_like_txid(text):
        order = book.open_for_chat(chat_id)
        if order is None:
            actions.reply(chat_id, "I have no open order for this chat. Send the licence "
                                   "request first, then the transaction id.")
            return actions
        order.txid = text
        order.claimed_at = stamp
        order.status = STATUS_CLAIMED
        actions.reply(chat_id, f"Thanks — {order.code} is marked as paid. I am checking the "
                               f"transaction now; the licence arrives in this chat shortly.")
        actions.reply(_seller_target(allowed),
                      f"💸 {order.code} claims payment\n{order.one_line()}\n"
                      f"check the wallet, then: /confirm {order.code} {order.txid[:24]}")
        actions.note(f"{order.code} marked claimed (txid {order.txid})")
        return actions

    # ── anything else ───────────────────────────────────────────────────────
    order = book.open_for_chat(chat_id)
    if order:
        actions.reply(chat_id, build_payment_reply(order, wallet, telegram))
        actions.note(f"re-sent payment details for {order.code} to {chat_id}")
    else:
        actions.reply(chat_id, "Send the request that `pentdeck license request` writes "
                               "(it starts with “pentdeck licence request”), or the "
                               "transaction id after paying.")
    return actions


def _bot_token() -> str:
    return os.environ.get("PENTDECK_BUY_BOT_TOKEN", "")


def _seller_target(allowed: Optional[Iterable[str]] = None) -> str:
    ids = seller_ids(allowed)
    return ids[0] if ids else ""


def _handle_seller_command(text: str, book: OrderBook, actions: Actions, stamp: str,
                           post: Callable[[str, str], Tuple[bool, str]],
                           deliver: Callable[[str, str], Tuple[bool, str]],
                           chat_id: str) -> None:
    parts = text.split()
    command = parts[0].lower().lstrip("/") if parts else ""
    arguments = parts[1:]

    if command in ("start", "help", ""):
        actions.reply(chat_id, HELP)
        return

    if command == "stats":
        stats = book.stats()
        actions.reply(chat_id,
                      f"orders {stats['orders']} · pending {stats['pending']} · "
                      f"delivered {stats['delivered']} · cancelled {stats['cancelled']} · "
                      f"${stats['revenue_usd']} collected")
        return

    if command in ("orders", "pending"):
        pending = book.pending()
        if not pending:
            actions.reply(chat_id, "nothing pending — every order is delivered or cancelled")
            return
        width = max(len(order.code) for order in pending)
        lines = [f"pending ({len(pending)}):"]
        for order in pending:
            lines.append(f"  {order.code:<{width}}  {order.tier:<5} ${order.price:<4} "
                         f"{order.status:<8} {order.name or ''} {order.email or ''}"
                         + (f"  txid {order.txid[:20]}" if order.txid else ""))
        lines += ["", "confirm one with: /confirm <code> [txid]"]
        actions.reply(chat_id, "\n".join(lines))
        return

    if command == "show":
        if not arguments:
            actions.reply(chat_id, "usage: /show PD-XXXX")
            return
        order = book.get(arguments[0])
        actions.reply(chat_id, json.dumps(order.as_dict(), indent=2, ensure_ascii=False)
                      if order else f"no order {arguments[0].upper()}")
        return

    if command in ("confirm", "issue"):
        if not arguments:
            actions.reply(chat_id, f"usage: /{command} PD-XXXX [txid]")
            return
        order = book.get(arguments[0])
        if order is None:
            actions.reply(chat_id, f"no order {arguments[0].upper()}")
            return
        if command == "confirm":
            if order.status == STATUS_CANCELLED:
                actions.reply(chat_id, f"{order.code} was cancelled — /issue {order.code} "
                                       f"if it should go out after all")
                return
            if len(arguments) > 1:
                order.txid = arguments[1]
            if not order.txid:
                actions.reply(chat_id, f"{order.code} has no transaction id yet — send it as "
                                       f"`/confirm {order.code} <txid>` after checking the wallet")
                return
            if not order.chat_id:
                actions.reply(chat_id,
                              f"{order.code} has no buyer chat, so there is nowhere to deliver "
                              f"it. Issue it from the shell with `pentdeck seller confirm "
                              f"{order.code}` — that prints the token for you to send by hand.")
                return
        ok, token_or_error = _issue(order, book, actions, stamp)
        if not ok:
            actions.reply(chat_id, f"{order.code}: {token_or_error}")
            return
        actions.note(f"{order.code}: token issued ({order.tier})")
        if not order.chat_id:                              # /issue without a buyer: hand it over here
            actions.reply(chat_id, f"{order.code} issued (no chat on file — send this to the "
                                   f"buyer yourself):\n\n{token_or_error}")
            return
        sent, detail = deliver(order.chat_id, token_or_error)
        if sent:
            order.status = STATUS_DELIVERED
            order.delivered_at = stamp
            actions.note(f"{order.code}: delivered to {order.chat_id}")
            actions.reply(chat_id, f"✅ {order.code} delivered to the buyer's chat")
        else:
            actions.note(f"{order.code}: delivery failed — {detail}")
            order.token = token_or_error
            actions.reply(chat_id,
                          f"{order.code}: the token was issued but the buyer's chat did not "
                          f"accept it ({detail}).\n\n{token_or_error}\n\n"
                          f"Send it by hand, then /confirm {order.code} again.")
        return

    if command == "cancel":
        if not arguments:
            actions.reply(chat_id, "usage: /cancel PD-XXXX [reason]")
            return
        order = book.get(arguments[0])
        if order is None:
            actions.reply(chat_id, f"no order {arguments[0].upper()}")
            return
        order.status = STATUS_CANCELLED
        if len(arguments) > 1:
            order.note = (order.note + " | " if order.note else "") + " ".join(arguments[1:])
        actions.reply(chat_id, f"{order.code} cancelled")
        actions.note(f"{order.code} cancelled")
        return

    actions.reply(chat_id, f"I do not know '/{command}'.\n\n{HELP}")


def _issue(order: Order, book: OrderBook, actions: Actions, stamp: str) -> Tuple[bool, str]:
    """Sign a token for this order. Returns (ok, token or the reason it failed)."""
    secret = os.environ.get("PENTDECK_LICENSE_SECRET", "")
    if not secret:
        from .license import load_secret
        try:
            secret = load_secret(book.home, required=False)
        except LicenseError as exc:                       # pragma: no cover - defensive
            return False, str(exc)
    if not secret:
        return False, ("no signing secret on this machine — set PENTDECK_LICENSE_SECRET or "
                       "keep ~/.pentdeck/secret next to this bot")
    days = 3650
    if order.tier == "team":
        days = 3650
    try:
        token = issue_token(secret, order.name or order.email or order.code, tier=order.tier,
                            days=days, order=order.code, machine=order.machine,
                            seats=int(TIERS[order.tier].get("operators", 1)))
    except LicenseError as exc:
        return False, str(exc)
    order.token = token
    return True, token


# ---------------------------------------------------------------------------
# the loop
# ---------------------------------------------------------------------------
def poll_once(book: OrderBook, token: str, *, home: Optional[pathlib.Path] = None,
              wallet: str = "", telegram: str = "", allowed: Optional[Iterable[str]] = None,
              sender: Optional[Callable[[str, str], Tuple[bool, str]]] = None,
              deliver: Optional[Callable[[str, str], Tuple[bool, str]]] = None,
              timeout: int = 0) -> List[str]:
    """Read the bot's inbox, act on it, save. Returns what happened.

    Losing this call does not lose an order: Telegram keeps updates until the offset
    moves past them, and the offset only moves after the book is on disk.
    """
    ok, messages, next_offset = collect_updates(token, book.offset, timeout=timeout)
    if not ok:
        return ["could not read from Telegram (bad token, or no network)"]

    notes: List[str] = []
    for message in messages:
        if int(message.get("update_id") or 0) < book.offset:
            continue
        actions = handle_message(message, book, wallet=wallet, telegram=telegram,
                                 allowed=allowed, sender=sender, deliver=deliver)
        for target, body in actions.sent:
            if not target:
                notes.append(f"nowhere to send: {body.splitlines()[0][:60]}")
                continue
            post = sender or (lambda chat, text: send_order(text, token, chat))
            sent, detail = post(target, body)
            notes.append(f"→ {target}: {'sent' if sent else detail}")
        notes.extend(actions.notes)

    if next_offset != book.offset:
        book.offset = next_offset
    book.save()
    return notes


def serve(token: str, home: Optional[pathlib.Path] = None, *, wallet: str = "",
          telegram: str = "", allowed: Optional[Iterable[str]] = None, poll_timeout: int = 25,
          once: bool = False, should_stop: Optional[Callable[[], bool]] = None,
          on_note: Optional[Callable[[str], None]] = None,
          sender: Optional[Callable[[str, str], Tuple[bool, str]]] = None,
          deliver: Optional[Callable[[str, str], Tuple[bool, str]]] = None) -> int:
    """Long-poll the bot until stopped. This is what `pentdeck seller run` calls."""
    if not token:
        raise ValueError("no bot token — set PENTDECK_BUY_BOT_TOKEN")
    book = OrderBook.load(home)
    if wallet:
        pass                       # the caller already resolved it
    print(f"pentdeck seller bot — {len(book.orders)} order(s) on file, offset {book.offset}")
    print("buyers send a request; /help lists the commands for you")
    while True:
        try:
            for note in poll_once(book, token, home=home, wallet=wallet, telegram=telegram,
                                  allowed=allowed, sender=sender, deliver=deliver,
                                  timeout=0 if once else poll_timeout):
                print(f"  {note}")
                if on_note:
                    on_note(note)
        except KeyboardInterrupt:
            print("\nstopping — orders are saved")
            book.save()
            return 0
        if once or (should_stop is not None and should_stop()):
            return 0


# ---------------------------------------------------------------------------
# the seller's own CLI, without the bot
# ---------------------------------------------------------------------------
def confirm_by_hand(code: str, home: Optional[pathlib.Path] = None, *, txid: str = "",
                    machine: str = "", send: bool = False,
                    sender: Optional[Callable[[str, str], Tuple[bool, str]]] = None,
                    deliver: Optional[Callable[[str, str], Tuple[bool, str]]] = None
                    ) -> Tuple[bool, str]:
    """`pentdeck seller confirm` — the same path the bot uses, driven from a shell."""
    book = OrderBook.load(home)
    order = book.get(code)
    if order is None:
        return False, f"no order {code.upper()}"
    if txid:
        order.txid = txid
    if machine:
        order.machine = machine
    actions = Actions()
    ok, token_or_error = _issue(order, book, actions, _now())
    if not ok:
        book.save()
        return False, token_or_error
    if send and order.chat_id:
        token = os.environ.get("PENTDECK_BUY_BOT_TOKEN", "")
        sender = sender or (lambda chat, text: send_license(text, token, chat))
        sent, detail = sender(order.chat_id, token_or_error)
        if sent:
            order.status = STATUS_DELIVERED
            order.delivered_at = _now()
            book.save()
            return True, f"{order.code}: delivered to {order.chat_id}\n\n{token_or_error}"
        book.save()
        return False, f"{order.code}: issued but not delivered ({detail})\n\n{token_or_error}"
    order.status = STATUS_DELIVERED if order.status == STATUS_CLAIMED else order.status
    book.save()
    return True, token_or_error
