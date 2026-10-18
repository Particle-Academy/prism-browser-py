"""G-89 (prism-browser-py#1): non-public addresses are refused EVEN WHEN ALLOW-LISTED.

This port judged an address by ``is_private``/``is_loopback``/``is_link_local``,
which leave out CGNAT (Alibaba Cloud's metadata endpoint), benchmarking,
multicast and documentation ranges, and know nothing of NAT64 or 6to4 spellings
of 169.254.169.254. Each host below is allow-listed by its parsed hostname, so
only the address check can refuse it.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from prism_browser import BrowserPolicy, BrowserRefused


def refusal(host: str) -> str:
    url = f"https://{host}/latest/meta-data"
    hostname = urlsplit(url).hostname
    assert hostname is not None
    policy = BrowserPolicy([hostname])
    try:
        policy.assert_url(url)
    except BrowserRefused as refused:
        return str(refused.code.value if hasattr(refused.code, "value") else refused.code)
    return "no_refusal"


@pytest.mark.parametrize(
    "host",
    [
        "169.254.169.254",
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.0.1",
        "0.1.2.3",
        "240.0.0.1",
        "100.100.100.200",
        "100.64.0.1",
        "192.0.0.170",
        "192.0.2.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "[::1]",
        "[::]",
        "[fd00::1]",
        "[fe80::1]",
        "[::ffff:127.0.0.1]",
        "[::7f00:1]",
        "[64:ff9b::a9fe:a9fe]",
        "[64:ff9b::169.254.169.254]",
        "[64:ff9b::7f00:1]",
        "[64:ff9b:1::a9fe:a9fe]",
        "[2002:a9fe:a9fe::]",
        "[2002:a00:5::1]",
        "[2001:0:4136:e378:8000:63bf:3fff:fdd2]",
        "[2001:db8::1]",
        "[100::1]",
        "[fec0::1]",
        "[ff02::1]",
        # Shorthand IPv4 a browser resolves to loopback without DNS.
        "127.1",
        "0x7f000001",
        "2130706433",
        "0177.0.0.1",
    ],
)
def test_non_public_address_is_refused_even_when_allow_listed(host: str) -> None:
    assert refusal(host) == "private_address_refused"


@pytest.mark.parametrize(
    "host",
    ["8.8.8.8", "[64:ff9b::808:808]", "[2002:808:808::1]", "[2606:4700:4700::1111]", "example.com"],
)
def test_public_hosts_still_navigate(host: str) -> None:
    assert refusal(host) == "no_refusal"
