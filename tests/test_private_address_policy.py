from __future__ import annotations

from typing import Any, cast

import pytest

from prism_browser import BrowserAction, BrowserPolicy, BrowserRefused, GuardedBrowser, Observation

TARGETS = [
    ["https://127.0.0.1/", ["127.0.0.1"]],
    ["https://localhost/", ["localhost"]],
    ["https://127.1/", ["127.1", "127.0.0.1"]],
    ["https://2130706433/", ["2130706433", "127.0.0.1"]],
    ["https://0x7f000001/", ["0x7f000001", "127.0.0.1"]],
    ["https://0177.0.0.1/", ["0177.0.0.1", "127.0.0.1"]],
    ["https://169.254.169.254/", ["169.254.169.254"]],
    ["https://100.100.100.200/", ["100.100.100.200"]],
    ["https://10.0.0.1/", ["10.0.0.1"]],
    ["https://[::1]/", ["[::1]", "::1"]],
    ["https://[64:ff9b::a9fe:a9fe]/", ["[64:ff9b::a9fe:a9fe]", "64:ff9b::a9fe:a9fe"]],
    ["https://[2002:a9fe:a9fe::1]/", ["[2002:a9fe:a9fe::1]", "2002:a9fe:a9fe::1"]],
]


class RecordingEngine:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def navigate(self, url: str) -> Observation:
        self.calls.append(url)
        return Observation(origin=url, url=url, title="Fixture", content={})

    def act(self, action: BrowserAction) -> Observation:
        raise AssertionError("Unexpected action")


@pytest.mark.parametrize("value", [True, False, None, 0, 1, "false"])
def test_rejects_retired_constructor_option(value: Any) -> None:
    legacy: dict[str, Any] = {"allow_private_addresses": value}
    with pytest.raises(TypeError):
        BrowserPolicy(["example.com"], **legacy)


@pytest.mark.parametrize(("url", "hosts"), TARGETS)
@pytest.mark.parametrize("assign_legacy", [False, True])
def test_refuses_private_target_before_engine(
    url: str, hosts: list[str], assign_legacy: bool
) -> None:
    policy = BrowserPolicy(hosts)
    if assign_legacy:
        cast(Any, policy).allow_private_addresses = True
    engine = RecordingEngine()
    with pytest.raises(BrowserRefused) as refused:
        GuardedBrowser(engine, policy).navigate(url)
    assert refused.value.code == "private_address_refused"
    assert engine.calls == []


@pytest.mark.parametrize("url", ["https://8.8.8.8/", "https://www.example.com/"])
def test_public_target_still_reaches_engine(url: str) -> None:
    engine = RecordingEngine()
    GuardedBrowser(engine, BrowserPolicy(["8.8.8.8", "*.example.com"])).navigate(url)
    assert engine.calls == [url]


def test_serializes_only_five_reference_policy_fields() -> None:
    policy = BrowserPolicy(["example.com"])
    assert not hasattr(policy, "allow_private_addresses")
    cast(Any, policy).allow_private_addresses = True
    assert set(policy.to_dict()) == {
        "allowed_actions",
        "allowed_hosts",
        "allowed_ports",
        "max_observation_bytes",
        "require_https",
    }
    with pytest.raises(BrowserRefused):
        policy.assert_url("https://127.0.0.1/")
