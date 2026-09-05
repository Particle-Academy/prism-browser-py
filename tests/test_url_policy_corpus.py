"""The cross-language URL-policy corpus from ``prism-parity``.

A refusal CODE is the contract -- a consumer switches on it to decide whether to
retry, widen an allow-list, or surface a hard stop. The message is not, and the
corpus deliberately does not pin it: three implementations word these
differently on purpose, and asserting the prose holds every language to a
translation.

G-21 IS CLOSED AND EVERY ROW NOW AGREES. Three of them used to be recorded as
divergences: all three languages refused the same URLs -- the security behaviour
was identical and every private address was blocked -- but the reference named
it ``private_network_refused`` and exposed it as ``$refused->reason``, where this
port has always said ``private_address_refused`` on ``.code``. The REFERENCE
moved, because the check is per-address rather than per-network. Nothing changed
in this port, only what it is allowed to expect of the reference.

Mirrors prism-browser-ts/test/url-policy-corpus.test.ts case for case.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from prism_browser import BrowserPolicy, BrowserRefused

CORPUS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "browser-url-policy.json").read_text(encoding="utf-8")
)
CASES: list[dict[str, Any]] = CORPUS["cases"]
PRIVATE_ADDRESS = [case for case in CASES if case["refusal"]["py"] == "private_address_refused"]


def _id(case: dict[str, Any]) -> str:
    return str(case["id"])


def _refusal_of(case: dict[str, Any]) -> str | None:
    policy = BrowserPolicy(
        allowed_hosts=case["policy"]["allowed_hosts"],
        require_https=case["policy"].get("require_https", True),
        allowed_ports=case["policy"].get("allowed_ports", [443]),
    )

    try:
        policy.assert_url(case["url"])
    except BrowserRefused as refused:
        return refused.code

    return None


def test_the_corpus_is_whole_not_a_subset_someone_trimmed_to_green() -> None:
    assert len(CASES) == 12


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_produces_this_languages_recorded_code(case: dict[str, Any]) -> None:
    assert _refusal_of(case) == case["refusal"]["py"]


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_agrees_with_the_php_reference(case: dict[str, Any]) -> None:
    assert _refusal_of(case) == case["refusal"]["php"]


def test_records_no_divergence_left_to_explain() -> None:
    # The list is asserted rather than the absence, so that a row quietly
    # flipped back to ``agrees: false`` fails here instead of being filtered
    # out silently everywhere else.
    assert [case["id"] for case in CASES if not case["agrees"]] == []


def test_refuses_every_private_address_on_exactly_the_rows_that_claim_to() -> None:
    # The security claim, stated independently of the code comparison. The
    # comparisons above only check that this language produces the string the
    # corpus recorded; if a change turned one of these into an ALLOW, the corpus
    # would be regenerated to record the allow and they would all stay green.
    # This is what would go red.
    assert [case["id"] for case in PRIVATE_ADDRESS] == ["url-0005", "url-0006", "url-0007"]

    for case in PRIVATE_ADDRESS:
        assert _refusal_of(case) == "private_address_refused", case["id"]


def test_never_answers_to_the_references_retired_name() -> None:
    for case in CASES:
        recorded = [case["refusal"][language] for language in ("php", "ts", "py")]
        assert "private_network_refused" not in recorded, case["id"]


def test_agrees_with_typescript_on_every_row() -> None:
    for case in CASES:
        assert case["refusal"]["py"] == case["refusal"]["ts"], case["id"]
