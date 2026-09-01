"""The cross-language URL-policy corpus from ``prism-parity``.

A refusal CODE is the contract -- a consumer switches on it to decide whether to
retry, widen an allow-list, or surface a hard stop. The message is not, and the
corpus deliberately does not pin it: three implementations word these
differently on purpose, and asserting the prose holds every language to a
translation.

The rows that diverge are asserted as DIVERGENCES rather than skipped. All three
languages refuse the same URLs -- the security behaviour is identical and every
private address is blocked -- but the reference names it
``private_network_refused`` and this port names it ``private_address_refused``.
See G-21.

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
AGREEING = [case for case in CASES if case["agrees"]]
DIVERGING = [case for case in CASES if not case["agrees"]]


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


@pytest.mark.parametrize("case", AGREEING, ids=_id)
def test_agrees_with_the_php_reference(case: dict[str, Any]) -> None:
    assert _refusal_of(case) == case["refusal"]["php"]


@pytest.mark.parametrize("case", DIVERGING, ids=_id)
def test_refuses_like_the_reference_but_names_it_differently(case: dict[str, Any]) -> None:
    # Two assertions, and both matter. The behaviour is identical -- every one
    # of these is refused in all three languages -- and only the code differs.
    # Asserting the refusal happened is what keeps this a naming finding rather
    # than letting a real hole hide behind the word "divergence".
    produced = _refusal_of(case)

    assert produced is not None
    assert produced != case["refusal"]["php"]


def test_diverges_on_exactly_the_three_rows_the_manifest_names() -> None:
    assert [case["id"] for case in DIVERGING] == ["url-0005", "url-0006", "url-0007"]


def test_refuses_every_private_address_in_the_corpus_whatever_it_calls_it() -> None:
    # The security claim, stated independently of the naming argument. If a
    # future rename accidentally turned one of these into an allow, the
    # divergence tests above would still pass -- they only compare codes.
    for case in DIVERGING:
        assert _refusal_of(case) is not None, case["id"]


def test_agrees_with_typescript_on_every_row() -> None:
    for case in CASES:
        assert case["refusal"]["py"] == case["refusal"]["ts"], case["id"]
