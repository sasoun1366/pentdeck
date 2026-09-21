"""The seller bot, tested without Telegram and without money.

Every test injects the two things that would otherwise touch the outside world — the
function that posts a reply and the function that delivers a licence — so the whole
buyer journey (request → transaction id → confirmation → signed token) runs here in
milliseconds. The bot's rules are the interesting part and they are all checkable:

* only the seller's own chat may confirm an order, and only the seller's chat sees the
  order list;
* a licence is issued *only* after the seller confirms a payment, never because a buyer
  said they paid;
* a buyer can only ever touch their own order.
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Dict, List, Tuple

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from pentdeck import cli, license as lic, purchase as pur, seller as sel   # noqa: E402

SECRET = "seller-bot-test-secret"
WALLET = "TMEyd1JZqdCjjKTc4zG2fhjzAYFKXCUWnA"
SELLER_CHAT = "999"
BUYER_CHAT = "555"


@pytest.fixture()
def home(tmp_path: pathlib.Path) -> pathlib.Path:
    """A seller's machine: a signing secret, a wallet, and nothing else yet."""
    directory = tmp_path / "home"
    directory.mkdir()
    (directory / "secret").write_text(SECRET + "\n", encoding="utf-8")
    pur.save_wallet(WALLET, directory)
    return directory


@pytest.fixture()
def sender():
    """Collects replies instead of sending them."""
    sent: List[Tuple[str, str]] = []

    def post(chat_id: str, text: str) -> Tuple[bool, str]:
        sent.append((str(chat_id), text))
        return True, f"message_id={len(sent)}"

    post.sent = sent                                     # type: ignore[attr-defined]
    return post


@pytest.fixture()
def deliver():
    delivered: List[Tuple[str, str]] = []

    def hand_over(chat_id: str, token: str) -> Tuple[bool, str]:
        delivered.append((str(chat_id), token))
        return True, "message_id=77"

    hand_over.delivered = delivered                     # type: ignore[attr-defined]
    return hand_over


def request_message(chat_id: str = BUYER_CHAT, tier: str = "pro", order: str = "PD-7K3Q",
                    name: str = "Acme IT", email: str = "it@acme.test",
                    machine: str = "") -> Dict[str, str]:
    """Exactly what `pentdeck license request` prints, pasted into the chat."""
    text = pur.build_request_text(name=name, email=email, tier=tier, order=order,
                                  note="please invoice", wallet=WALLET,
                                  telegram="https://t.me/luyavaai")
    if machine:
        text = text.replace("After paying", f"machine : {machine}\n\nAfter paying")
    return {"update_id": 1, "chat_id": chat_id, "username": "buyer1", "text": text}


def message(text: str, chat_id: str = BUYER_CHAT, update_id: int = 2) -> Dict[str, str]:
    return {"update_id": update_id, "chat_id": chat_id, "username": "buyer1", "text": text}


def handle(book: sel.OrderBook, msg: Dict[str, str], sender, deliver, **kwargs) -> sel.Actions:
    """Handle one message, and post what it asked to post.

    `handle_message` is pure bookkeeping: it returns the replies it wants sent. The loop
    does the sending (see `poll_once`, tested below), so this helper does the same thing
    the loop does — that way a test can look at one list of what the buyer and the seller
    would actually receive.
    """
    actions = sel.handle_message(msg, book, wallet=WALLET, telegram="https://t.me/luyavaai",
                                 allowed=[SELLER_CHAT], sender=sender, deliver=deliver, **kwargs)
    for target, text in actions.sent:
        sender(target, text)
    return actions


def replies_to(sender, chat_id: str) -> List[str]:
    return [text for target, text in sender.sent if target == str(chat_id)]


# ---------------------------------------------------------------------------
# the order book
# ---------------------------------------------------------------------------
def test_an_order_is_written_once_and_read_back(tmp_path):
    book = sel.OrderBook(tmp_path)
    book.add(sel.Order(code="PD-AAAA", name="Acme", email="it@acme.test", tier="pro", chat_id="1"))
    book.offset = 42
    path = book.save()
    assert (path.stat().st_mode & 0o777) == 0o600        # buyers' data is not world readable
    again = sel.OrderBook.load(tmp_path)
    assert again.offset == 42
    assert again.get("pd-aaaa") is not None              # lookup is case-insensitive
    assert again.get("PD-AAAA").name == "Acme"
    assert again.get("PD-ZZZZ") is None


def test_a_broken_order_file_does_not_take_the_bot_down(tmp_path):
    (tmp_path / sel.ORDER_FILENAME).write_text("{not json", encoding="utf-8")
    book = sel.OrderBook.load(tmp_path)
    assert book.orders == [] and book.offset == 0


def test_stats_count_only_delivered_money(tmp_path):
    book = sel.OrderBook(tmp_path)
    book.add(sel.Order(code="PD-1", tier="pro", status=sel.STATUS_DELIVERED))
    book.add(sel.Order(code="PD-2", tier="team", status=sel.STATUS_CLAIMED))
    book.add(sel.Order(code="PD-3", tier="pro", status=sel.STATUS_CANCELLED))
    stats = book.stats()
    assert stats["orders"] == 3 and stats["delivered"] == 1
    assert stats["revenue_usd"] == 99                     # the claim is not money yet
    assert stats["pending"] == 1


# ---------------------------------------------------------------------------
# who may do what
# ---------------------------------------------------------------------------
def test_only_the_sellers_chat_is_the_seller(monkeypatch):
    monkeypatch.setenv("PENTDECK_BUY_CHAT_ID", SELLER_CHAT)
    monkeypatch.setenv("PENTDECK_SELLER_IDS", "111, 222")
    assert sel.is_seller(SELLER_CHAT) and sel.is_seller("111") and sel.is_seller("222")
    assert not sel.is_seller(BUYER_CHAT)
    monkeypatch.delenv("PENTDECK_BUY_CHAT_ID")
    assert not sel.is_seller(SELLER_CHAT)


def test_a_buyer_cannot_confirm_their_own_order(book_with_order, sender, deliver):
    book = book_with_order
    handle(book, message("/confirm PD-7K3Q deadbeef"), sender, deliver)
    assert book.get("PD-7K3Q").status == sel.STATUS_CLAIMED      # untouched
    assert book.get("PD-7K3Q").token == ""
    assert not deliver.delivered
    assert "takes pentdeck licence orders" in replies_to(sender, BUYER_CHAT)[0]


def test_a_buyer_cannot_see_the_order_list(book_with_order, sender, deliver):
    handle(book_with_order, message("/orders"), sender, deliver)
    assert "pending" not in "\n".join(replies_to(sender, BUYER_CHAT))
    assert not replies_to(sender, SELLER_CHAT)


@pytest.fixture()
def book_with_order(home):
    """A buyer who has already sent a request and a transaction id."""
    book = sel.OrderBook(home)
    book.offset = 1
    book.add(sel.Order(code="PD-7K3Q", name="Acme IT", email="it@acme.test", tier="pro",
                       chat_id=BUYER_CHAT, created="2026-09-21T10:00:00+00:00",
                       status=sel.STATUS_CLAIMED, txid="a" * 64))
    book.save()
    return book


# ---------------------------------------------------------------------------
# the buyer journey
# ---------------------------------------------------------------------------
def test_a_request_creates_the_order_and_answers_the_buyer(home, sender, deliver):
    book = sel.OrderBook(home)
    actions = handle(book, request_message(), sender, deliver)

    order = book.get("PD-7K3Q")
    assert order is not None
    assert (order.name, order.email, order.tier, order.chat_id) == ("Acme IT", "it@acme.test", "pro", BUYER_CHAT)
    assert order.status == sel.STATUS_NEW

    buyer_reply = replies_to(sender, BUYER_CHAT)[0]
    assert "PD-7K3Q" in buyer_reply and WALLET in buyer_reply
    assert "99 USDT (TRC20)" in buyer_reply
    assert "transaction id" in buyer_reply
    assert any("new order PD-7K3Q" in note for note in actions.notes)
    assert "order PD-7K3Q" in replies_to(sender, SELLER_CHAT)[0]


def test_the_code_from_the_request_is_kept_but_a_missing_one_is_replaced(home, sender, deliver):
    book = sel.OrderBook(home)
    text = pur.build_request_text(name="A", email="a@b.test", tier="team", order="",
                                  wallet=WALLET)
    handle(book, {"update_id": 1, "chat_id": BUYER_CHAT, "text": text}, sender, deliver)
    order = book.orders[0]
    assert order.tier == "team" and order.code.startswith("PD-")
    assert "299 USDT" in replies_to(sender, BUYER_CHAT)[0]


def test_the_same_request_twice_does_not_create_two_orders(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(), sender, deliver)
    handle(book, request_message(order="PD-DIFF"), sender, deliver)
    assert len(book.orders) == 1
    assert any("restated" in note for note in handle(book, request_message(), sender, deliver).notes)


def test_an_unknown_tier_is_refused_with_the_real_ones(home, sender, deliver):
    book = sel.OrderBook(home)
    text = pur.build_request_text(name="A", email="a@b.test", tier="free", order="PD-X")
    actions = handle(book, {"update_id": 1, "chat_id": BUYER_CHAT, "text": text}, sender, deliver)
    assert book.orders == []
    assert "'free' is not a tier I sell" in replies_to(sender, BUYER_CHAT)[0]
    assert "pro" in replies_to(sender, BUYER_CHAT)[0] and "team" in replies_to(sender, BUYER_CHAT)[0]


def test_a_transaction_id_marks_the_order_claimed_and_tells_the_seller(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(), sender, deliver)
    actions = handle(book, message("0x" + "b" * 62), sender, deliver)

    order = book.get("PD-7K3Q")
    assert order.status == sel.STATUS_CLAIMED
    assert order.txid == "0x" + "b" * 62
    assert "marked as paid" in replies_to(sender, BUYER_CHAT)[-1]
    seller_notes = [text for target, text in sender.sent if target == SELLER_CHAT]
    assert any("claims payment" in text for text in seller_notes)
    assert any("/confirm PD-7K3Q" in text for text in seller_notes)
    assert any("marked claimed" in note for note in actions.notes)


def test_a_transaction_id_without_an_order_is_explained(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, message("a" * 64), sender, deliver)
    assert "no open order" in replies_to(sender, BUYER_CHAT)[0]


def test_chit_chat_from_a_buyer_with_an_order_repeats_the_payment_details(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(), sender, deliver)
    handle(book, message("salam, chera dir kard?"), sender, deliver)
    assert WALLET in replies_to(sender, BUYER_CHAT)[-1]


def test_chit_chat_from_a_stranger_gets_pointed_at_the_request(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, message("hello?"), sender, deliver)
    assert "pentdeck licence request" in replies_to(sender, BUYER_CHAT)[0]


# ---------------------------------------------------------------------------
# the confirmation — the only thing that issues a licence
# ---------------------------------------------------------------------------
def test_nothing_is_issued_before_the_seller_confirms(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(), sender, deliver)
    handle(book, message("c" * 64), sender, deliver)
    assert book.get("PD-7K3Q").token == ""
    assert deliver.delivered == []


def test_confirm_issues_a_real_token_and_delivers_it(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(), sender, deliver)
    handle(book, message("a" * 64), sender, deliver)
    handle(book, message("/confirm PD-7K3Q", SELLER_CHAT, 3), sender, deliver)

    order = book.get("PD-7K3Q")
    assert order.status == sel.STATUS_DELIVERED and order.delivered_at
    assert deliver.delivered == [(BUYER_CHAT, order.token)]
    # the token is a real one: it verifies, and it carries this order
    verified = lic.decode_token(order.token, SECRET)
    assert verified.tier == "pro" and verified.order == "PD-7K3Q"
    assert verified.customer == "Acme IT"
    assert any("delivered to the buyer's chat" in text for text in replies_to(sender, SELLER_CHAT))


def test_confirm_refuses_without_a_transaction_id(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(), sender, deliver)
    handle(book, message("/confirm PD-7K3Q", SELLER_CHAT, 3), sender, deliver)
    assert book.get("PD-7K3Q").status == sel.STATUS_NEW
    assert not deliver.delivered
    assert "no transaction id" in replies_to(sender, SELLER_CHAT)[-1]


def test_confirm_takes_the_txid_on_the_command_line_too(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(), sender, deliver)
    handle(book, message(f"/confirm PD-7K3Q {'d' * 64}", SELLER_CHAT, 3), sender, deliver)
    order = book.get("PD-7K3Q")
    assert order.status == sel.STATUS_DELIVERED and order.txid == "d" * 64


def test_a_failed_delivery_gives_the_seller_the_token_to_send_by_hand(home, sender):
    book = sel.OrderBook(home)

    def refusing_delivery(chat_id, token):
        return False, "HTTP 403: bot was blocked by the user"

    handle(book, request_message(), sender, refusing_delivery)
    handle(book, message("a" * 64), sender, refusing_delivery)
    handle(book, message("/confirm PD-7K3Q", SELLER_CHAT, 3), sender, refusing_delivery)

    order = book.get("PD-7K3Q")
    assert order.status == sel.STATUS_CLAIMED               # not delivered
    assert order.token.startswith("PD1.")                   # but issued, and not lost
    assert order.token in replies_to(sender, SELLER_CHAT)[-1]


def test_confirm_needs_an_address_to_deliver_to(home, sender, deliver):
    book = sel.OrderBook(home)
    book.add(sel.Order(code="PD-NOCHAT", tier="pro", name="Walk-in", txid="a" * 64))
    handle(book, message("/confirm PD-NOCHAT", SELLER_CHAT, 3), sender, deliver)
    assert "no buyer chat" in replies_to(sender, SELLER_CHAT)[-1]
    assert "pentdeck seller confirm PD-NOCHAT" in replies_to(sender, SELLER_CHAT)[-1]
    assert book.get("PD-NOCHAT").status == sel.STATUS_NEW      # nothing went out


def test_issue_without_a_chat_hands_the_token_to_the_seller(home, sender, deliver):
    book = sel.OrderBook(home)
    book.add(sel.Order(code="PD-WALK", tier="pro", name="Walk-in", email="w@x.test"))
    handle(book, message("/issue PD-WALK", SELLER_CHAT, 3), sender, deliver)
    reply = replies_to(sender, SELLER_CHAT)[-1]
    token = [line for line in reply.splitlines() if line.startswith("PD1.")][0]
    assert lic.decode_token(token, SECRET).customer == "Walk-in"
    assert book.get("PD-WALK").token == token
    assert not deliver.delivered                               # no chat to deliver to


def test_a_cancelled_order_is_not_confirmed_by_accident(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(), sender, deliver)
    handle(book, message("a" * 64), sender, deliver)
    handle(book, message("/cancel PD-7K3Q refunded", SELLER_CHAT, 3), sender, deliver)
    assert book.get("PD-7K3Q").status == sel.STATUS_CANCELLED
    handle(book, message("/confirm PD-7K3Q", SELLER_CHAT, 4), sender, deliver)
    assert book.get("PD-7K3Q").status == sel.STATUS_CANCELLED
    assert not deliver.delivered
    assert "was cancelled" in replies_to(sender, SELLER_CHAT)[-1]


def test_issue_re_issues_and_still_delivers(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(), sender, deliver)
    handle(book, message("a" * 64), sender, deliver)
    handle(book, message("/issue PD-7K3Q", SELLER_CHAT, 3), sender, deliver)
    first = deliver.delivered[-1][1]
    handle(book, message("/issue PD-7K3Q", SELLER_CHAT, 4), sender, deliver)
    second = deliver.delivered[-1][1]
    assert first != second                                   # a fresh nonce each time
    assert lic.decode_token(second, SECRET).tier == "pro"


def test_a_machine_bound_request_produces_a_machine_bound_licence(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(machine="ab12cd34ef56"), sender, deliver)
    assert book.get("PD-7K3Q").machine == "ab12cd34ef56"
    handle(book, message("a" * 64), sender, deliver)
    handle(book, message("/confirm PD-7K3Q", SELLER_CHAT, 3), sender, deliver)
    token = book.get("PD-7K3Q").token
    assert lic.decode_token(token, SECRET, machine="ab12cd34ef56").tier == "pro"
    with pytest.raises(lic.LicenseError):
        lic.decode_token(token, SECRET, machine="a-different-machine")


def test_a_team_licence_carries_the_seats(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(tier="team"), sender, deliver)
    handle(book, message("a" * 64), sender, deliver)
    handle(book, message("/confirm PD-7K3Q", SELLER_CHAT, 3), sender, deliver)
    verified = lic.decode_token(book.get("PD-7K3Q").token, SECRET)
    assert verified.tier == "team" and verified.seats == 25


def test_without_a_signing_secret_the_seller_is_told_what_to_do(tmp_path, sender, deliver, monkeypatch):
    empty = tmp_path / "no-secret"
    empty.mkdir()
    monkeypatch.delenv("PENTDECK_LICENSE_SECRET", raising=False)
    book = sel.OrderBook(empty)
    handle(book, request_message(), sender, deliver)
    handle(book, message("a" * 64), sender, deliver)
    handle(book, message("/confirm PD-7K3Q", SELLER_CHAT, 3), sender, deliver)
    assert "no signing secret" in replies_to(sender, SELLER_CHAT)[-1]
    assert not deliver.delivered
    assert book.get("PD-7K3Q").token == ""


# ---------------------------------------------------------------------------
# the seller's commands
# ---------------------------------------------------------------------------
def test_help_lists_the_commands(home, sender, deliver):
    book = sel.OrderBook(home)
    for text in ("/help", "/start", ""):
        handle(book, message(text, SELLER_CHAT), sender, deliver)
    assert all("/confirm PD-XXXX" in replies_to(sender, SELLER_CHAT)[i] for i in range(3))


def test_orders_lists_only_what_is_pending(home, sender, deliver):
    book = sel.OrderBook(home)
    book.add(sel.Order(code="PD-AAAA", tier="pro", name="One", status=sel.STATUS_CLAIMED,
                       txid="e" * 64, email="one@x.test"))
    book.add(sel.Order(code="PD-BBBB", tier="team", name="Done", status=sel.STATUS_DELIVERED))
    handle(book, message("/orders", SELLER_CHAT), sender, deliver)
    listing = replies_to(sender, SELLER_CHAT)[-1]
    assert "PD-AAAA" in listing and "PD-BBBB" not in listing
    assert "confirm one with" in listing


def test_orders_says_so_when_there_is_nothing_to_do(tmp_path, sender, deliver):
    book = sel.OrderBook(tmp_path)
    handle(book, message("/orders", SELLER_CHAT), sender, deliver)
    assert "nothing pending" in replies_to(sender, SELLER_CHAT)[-1]


def test_stats_reports_money_only_from_delivered_orders(home, sender, deliver):
    book = sel.OrderBook(home)
    book.add(sel.Order(code="PD-AAAA", tier="pro", status=sel.STATUS_DELIVERED))
    book.add(sel.Order(code="PD-BBBB", tier="team", status=sel.STATUS_CLAIMED))
    handle(book, message("/stats", SELLER_CHAT), sender, deliver)
    summary = replies_to(sender, SELLER_CHAT)[-1]
    assert "$99 collected" in summary and "pending 1" in summary


def test_show_prints_the_whole_order(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(), sender, deliver)
    handle(book, message("/show PD-7K3Q", SELLER_CHAT, 3), sender, deliver)
    payload = json.loads(replies_to(sender, SELLER_CHAT)[-1])
    assert payload["code"] == "PD-7K3Q" and payload["email"] == "it@acme.test"


def test_an_unknown_command_gets_help_rather_than_silence(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, message("/nonsense", SELLER_CHAT), sender, deliver)
    assert "do not know" in replies_to(sender, SELLER_CHAT)[-1]
    assert "/help" in replies_to(sender, SELLER_CHAT)[-1]


def test_confirming_an_order_that_does_not_exist_is_safe(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, message("/confirm PD-ZZZZ", SELLER_CHAT), sender, deliver)
    assert "no order PD-ZZZZ" in replies_to(sender, SELLER_CHAT)[-1]
    assert not deliver.delivered


# ---------------------------------------------------------------------------
# the loop: offsets, deduplication, and the whole journey in one pass
# ---------------------------------------------------------------------------
def test_poll_once_runs_the_whole_journey_and_verifies_the_token(home, sender, deliver, monkeypatch):
    """request → txid → /confirm, through the real polling path with a fake inbox."""
    inbox: List[Dict[str, str]] = [
        request_message(),
        message("a" * 64, update_id=2),
        message("/confirm PD-7K3Q", SELLER_CHAT, 3),
    ]

    monkeypatch.setattr(sel, "collect_updates", lambda token, offset, timeout=0: (
        True, [item for item in inbox if int(item["update_id"]) >= offset], 4))

    book = sel.OrderBook(home)
    notes = sel.poll_once(book, "TOKEN", home=home, wallet=WALLET,
                          telegram="https://t.me/luyavaai", allowed=[SELLER_CHAT],
                          sender=sender, deliver=deliver)

    order = book.get("PD-7K3Q")
    assert order.status == sel.STATUS_DELIVERED
    assert deliver.delivered == [(BUYER_CHAT, order.token)]
    assert lic.decode_token(order.token, SECRET).order == "PD-7K3Q"
    assert book.offset == 4                                   # the offset moved, once
    assert (home / sel.ORDER_FILENAME).exists()
    assert any("sent" in note for note in notes)

    # a second pass with the same inbox does nothing: the offset is past it
    again = sel.poll_once(book, "TOKEN", home=home, wallet=WALLET, allowed=[SELLER_CHAT],
                          sender=sender, deliver=deliver)
    assert again == ["could not read from Telegram (bad token, or no network)"] or again == [] or all(
        "sent" not in note for note in again)
    assert len(book.orders) == 1


def test_poll_once_keeps_the_offset_when_telegram_fails(home, monkeypatch):
    monkeypatch.setattr(sel, "collect_updates", lambda token, offset, timeout=0: (False, [], offset))
    book = sel.OrderBook(home)
    book.offset = 9
    notes = sel.poll_once(book, "TOKEN", home=home)
    assert book.offset == 9 and "could not read" in notes[0]


def test_a_buyer_with_nowhere_to_report_is_honest_about_it(home, sender, deliver, monkeypatch):
    """No seller chat id: the buyer still gets served, the order is still recorded."""
    monkeypatch.setattr(sel, "collect_updates", lambda token, offset, timeout=0: (
        True, [request_message()], 2))
    book = sel.OrderBook(home)
    notes = sel.poll_once(book, "TOKEN", home=home, wallet=WALLET, allowed=[],
                          sender=sender, deliver=deliver)
    assert book.get("PD-7K3Q") is not None
    assert any("nowhere to send" in note for note in notes)


# ---------------------------------------------------------------------------
# without the bot: the same work from a shell
# ---------------------------------------------------------------------------
def test_confirm_by_hand_issues_without_a_chat(home):
    book = sel.OrderBook(home)
    book.add(sel.Order(code="PD-WALK", name="Walk-in", email="w@x.test", tier="pro"))
    book.save()
    ok, message = sel.confirm_by_hand("PD-walk", home)
    assert ok and message.startswith("PD1.")
    assert lic.decode_token(message, SECRET).customer == "Walk-in"
    assert sel.OrderBook.load(home).get("PD-WALK").token == message


def test_confirm_by_hand_can_deliver_too(home):
    book = sel.OrderBook(home)
    book.add(sel.Order(code="PD-CHAT", name="Acme", email="a@x.test", tier="pro", chat_id=BUYER_CHAT))
    book.save()
    delivered: List[Tuple[str, str]] = []
    ok, message = sel.confirm_by_hand(
        "PD-CHAT", home, txid="f" * 64, send=True,
        sender=lambda chat, text: (delivered.append((chat, text)), (True, "ok"))[1])
    assert ok and delivered and delivered[0][0] == BUYER_CHAT
    assert sel.OrderBook.load(home).get("PD-CHAT").status == sel.STATUS_DELIVERED


# ---------------------------------------------------------------------------
# the command line around it
# ---------------------------------------------------------------------------
def test_the_seller_commands_work_from_the_cli(home, capsys):
    book = sel.OrderBook(home)
    book.add(sel.Order(code="PD-CLI1", name="Acme", email="a@x.test", tier="pro", chat_id=BUYER_CHAT))
    book.save()

    assert cli.main(["--home", str(home), "seller", "orders"]) == 0
    assert "PD-CLI1" in capsys.readouterr().out

    assert cli.main(["--home", str(home), "seller", "show", "PD-CLI1"]) == 0
    assert json.loads(capsys.readouterr().out)["code"] == "PD-CLI1"

    assert cli.main(["--home", str(home), "seller", "confirm", "PD-CLI1", "--txid", "a" * 64]) == 0
    token = capsys.readouterr().out.strip()
    assert token.startswith("PD1.") and lic.decode_token(token, SECRET).tier == "pro"

    assert cli.main(["--home", str(home), "seller", "stats"]) == 0
    assert "orders    : 1" in capsys.readouterr().out


def test_the_cli_explains_what_the_bot_needs(home, capsys, monkeypatch):
    monkeypatch.delenv("PENTDECK_BUY_BOT_TOKEN", raising=False)
    code = cli.main(["--home", str(home), "seller", "run", "--once"])
    assert code == 2
    assert "PENTDECK_BUY_BOT_TOKEN" in capsys.readouterr().err

    monkeypatch.setenv("PENTDECK_BUY_BOT_TOKEN", "123:abc")
    monkeypatch.delenv("PENTDECK_BUY_CHAT_ID", raising=False)
    code = cli.main(["--home", str(home), "seller", "run", "--once"])
    assert code == 2
    assert "PENTDECK_BUY_CHAT_ID" in capsys.readouterr().err


def test_the_orders_file_never_holds_the_secret(home, sender, deliver):
    book = sel.OrderBook(home)
    handle(book, request_message(), sender, deliver)
    handle(book, message("a" * 64), sender, deliver)
    handle(book, message("/confirm PD-7K3Q", SELLER_CHAT, 3), sender, deliver)
    book.save()
    written = (home / sel.ORDER_FILENAME).read_text(encoding="utf-8")
    assert SECRET not in written
    assert "PD1." in written                                  # the issued token is kept
    assert json.loads(written)["offset"] == 0
