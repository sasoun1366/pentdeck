"""Buying and selling: the request that reaches the seller, and the licence that comes back.

There is no payment gateway here, on purpose. A small tool sold for $99 does not
need Stripe, a merchant account, or a compliance department — it needs a wallet
address, an order code, and a human at the other end who checks the transaction
and sends a signed token. That is what this module automates: the bookkeeping and
the messaging, not the trust.

The seller side runs a bot. Two environment variables on the seller's machine:

    PENTDECK_BUY_BOT_TOKEN   the bot token (the same bot the channel uses is fine)
    PENTDECK_BUY_CHAT_ID     where orders should arrive (your own user id)

The buyer side needs nothing: they read the address and the order code off the
screen, pay, and message the bot.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .license import TIERS

DEFAULT_API = "https://api.telegram.org"

#: Where the seller's address lives when it is not in the environment. It is kept in
#: the state directory next to the licence secret: write it once per machine and every
#: request, every order and the dashboard all use it.
WALLET_FILENAME = "wallet"
TELEGRAM_FILENAME = "telegram"
DEFAULT_TELEGRAM = "https://t.me/luyavaai"

#: A TRON address: base58, starts with T, 34 characters. Only used to warn about a
#: typo — the seller may deliberately use another rail, so this never blocks.
_TRC20 = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")


def looks_like_trc20(address: str) -> bool:
    """True when the address has the shape of a USDT (TRC20) address."""
    return bool(_TRC20.match((address or "").strip()))


def wallet_file(home: Optional[pathlib.Path] = None) -> pathlib.Path:
    root = pathlib.Path(home) if home else pathlib.Path.home() / ".pentdeck"
    return root / WALLET_FILENAME


def telegram_file(home: Optional[pathlib.Path] = None) -> pathlib.Path:
    root = pathlib.Path(home) if home else pathlib.Path.home() / ".pentdeck"
    return root / TELEGRAM_FILENAME


def _stored(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def load_wallet(home: Optional[pathlib.Path] = None) -> str:
    """The address to be paid at: the environment first, then the stored file."""
    return (os.environ.get("PENTDECK_WALLET", "").strip()
            or _stored(wallet_file(home)))


def load_telegram(home: Optional[pathlib.Path] = None) -> str:
    """Where buyers ask questions. Same precedence as the wallet."""
    return (os.environ.get("PENTDECK_TELEGRAM", "").strip()
            or _stored(telegram_file(home))
            or DEFAULT_TELEGRAM)


def save_wallet(address: str, home: Optional[pathlib.Path] = None) -> pathlib.Path:
    """Store the address (mode 0600). An empty string removes it."""
    path = wallet_file(home)
    text = (address or "").strip()
    if not text:
        if path.exists():
            path.unlink()
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def save_telegram(url: str, home: Optional[pathlib.Path] = None) -> pathlib.Path:
    path = telegram_file(home)
    text = (url or "").strip()
    if not text:
        if path.exists():
            path.unlink()
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def order_code(prefix: str = "PD") -> str:
    """A short, unambiguous code — no vowels, so it cannot spell anything odd."""
    alphabet = "23456789BCDFGHJKLMNPQRSTVWXZ"
    body = "".join(secrets.choice(alphabet) for _ in range(4))
    return f"{prefix}-{body}"


def build_request_text(name: str, email: str, tier: str, order: str, note: str = "",
                       wallet: str = "", telegram: str = "") -> str:
    """What the buyer copies into the chat. Plain text: it must be readable anywhere."""
    price = TIERS.get(tier, TIERS["pro"])["price_usd"]
    lines = [
        "🛒 pentdeck licence request",
        f"order   : {order}",
        f"name    : {name}",
        f"email   : {email}",
        f"tier    : {tier} (${price})",
        f"amount  : {price} USDT (TRC20)",
        f"wallet  : {wallet or '(ask the seller)'}",
        f"memo    : {order}",
    ]
    if note:
        lines.append(f"note    : {note}")
    if telegram:
        lines.append(f"contact : {telegram}")
    lines.append("")
    lines.append("After paying, send the transaction id (txid) in this chat.")
    return "\n".join(lines)


def _api_base(api_base: Optional[str] = None) -> str:
    return (api_base or os.environ.get("PENTDECK_TELEGRAM_API") or DEFAULT_API).rstrip("/")


def send_order(text: str, token: str, chat_id: str, api_base: Optional[str] = None,
               timeout: float = 10.0) -> Tuple[bool, str]:
    """Post the request to the seller's bot chat. Never raises."""
    if not token or not chat_id:
        return False, "no bot token or chat id"
    url = f"{_api_base(api_base)}/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    request = urllib.request.Request(  # noqa: S310 - the Telegram API, or the user's own base
        url, data=json.dumps(payload).encode(), method="POST"
    )
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = json.loads(response.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:200]}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, str(exc)
    if not body.get("ok"):
        return False, str(body.get("description", body))
    message_id = (body.get("result") or {}).get("message_id")
    return True, f"message_id={message_id}"


def send_license(text: str, token: str, chat_id: str, api_base: Optional[str] = None,
                 timeout: float = 10.0) -> Tuple[bool, str]:
    """Seller side: send the issued token back to the buyer with a short wrapping."""
    message = (
        "✅ Your pentdeck licence\n\n"
        f"{text}\n\n"
        "Install it with:\n"
        f"  pentdeck license install {text.strip()}\n\n"
        "Keep it: it is signed, so nobody can edit it into something else."
    )
    return send_order(message, token, chat_id, api_base, timeout)


def collect_updates(token: str, offset: int = 0, timeout: int = 0,
                    api_base: Optional[str] = None, limit: int = 20) -> Tuple[bool, List[Dict[str, Any]], int]:
    """Seller side: read new messages from the bot.

    Returns (ok, messages, next_offset). Each message is a plain dict:
    {'update_id', 'chat_id', 'from_name', 'text'}.
    """
    if not token:
        return False, [], offset
    url = f"{_api_base(api_base)}/bot{token}/getUpdates?" + urllib.parse.urlencode(
        {"offset": offset, "timeout": timeout, "limit": limit}
    )
    try:
        with urllib.request.urlopen(url, timeout=max(5, timeout + 5)) as response:  # noqa: S310
            body = json.loads(response.read().decode() or "{}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, [], offset
    if not body.get("ok"):
        return False, [], offset
    messages: List[Dict[str, Any]] = []
    next_offset = offset
    for update in body.get("result", []):
        next_offset = max(next_offset, int(update.get("update_id", 0)) + 1)
        message = update.get("message") or update.get("edited_message") or {}
        if not message:
            continue
        sender = message.get("from") or {}
        messages.append({
            "update_id": update.get("update_id"),
            "chat_id": str((message.get("chat") or {}).get("id", "")),
            "from_name": " ".join(
                part for part in (sender.get("first_name"), sender.get("last_name")) if part
            ) or str(sender.get("username") or ""),
            "username": str(sender.get("username") or ""),
            "text": str(message.get("text") or ""),
        })
    return True, messages, next_offset


def parse_order_message(text: str) -> Optional[Dict[str, str]]:
    """Pull the fields out of a pasted request — for the seller's inbox."""
    fields: Dict[str, str] = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower().replace(" ", "_")
        if key in ("order", "name", "email", "tier", "note", "txid", "memo"):
            fields[key] = value.strip()
    if not fields:
        return None
    return fields


def format_inbox_message(message: Dict[str, Any]) -> str:
    """One line per arriving order, for the seller's terminal."""
    fields = parse_order_message(message.get("text", ""))
    who = message.get("from_name") or message.get("username") or "?"
    if fields:
        return (f"[{message.get('chat_id')}] {who}: order {fields.get('order', '?')} "
                f"— {fields.get('tier', '?')} — {fields.get('email', '?')}")
    return f"[{message.get('chat_id')}] {who}: {message.get('text', '')[:80]}"
