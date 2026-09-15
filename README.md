# Prism Browser for Python

A policy-bounded browser surface for agents. The Python port of
[`particle-academy/prism-browser`](https://github.com/Particle-Academy/prism-browser).

Zero runtime dependencies. Python 3.10+.

```
pip install prism-ai-browser
```

```python
from prism_browser import ActionKind, BrowserAction, BrowserPolicy, BrowserRefused, GuardedBrowser

policy = BrowserPolicy(
    allowed_hosts=["docs.example.com", "*.example.org"],
    allowed_actions=[ActionKind.CLICK, ActionKind.SCROLL],
)

browser = GuardedBrowser(my_engine, policy)

try:
    observation = browser.navigate("https://docs.example.com/start")
except BrowserRefused as refused:
    print(refused.code)
```

The package does not drive a browser itself. `my_engine` is anything that
implements the `BrowserEngine` protocol: `navigate(url)` and `act(action)`, each
returning an `Observation`.

## The policy

`BrowserPolicy` answers two questions before the engine receives anything: where
the agent may go, and what it may do there.

- **Hosts** are an allow-list. `*.example.org` matches subdomains, not
  `example.org` itself.
- **HTTPS** is required by default.
- **Ports** default to 443 only.
- **URLs with credentials** (`https://user:pass@host`) are refused.
- **Private, loopback and link-local addresses** are refused by default,
  including `localhost` and the cloud metadata address `169.254.169.254`.
  `allow_private_addresses=True` turns that off.
- **Actions** are an allow-list of `click`, `fill`, `select`, `press`, `scroll`
  and `hover`. All six are allowed unless you pass `allowed_actions`.

A refusal raises `BrowserRefused` with a stable `code`: `invalid_url`,
`url_credentials_refused`, `https_required`, `host_not_allowed`,
`port_not_allowed`, `private_address_refused`, `action_not_allowed`,
`observation_too_large`.

## Observations

`GuardedBrowser` passes every observation through an `ObservationGuard` before
returning it:

- An observation over `max_observation_bytes` (65,536 by default) is refused,
  not truncated.
- The page is returned as JSON inside an `<untrusted-browser-observation>`
  wrapper tagged with a random id, so page content cannot close the wrapper.

The wrapper makes a prompt injection harder. It does not make one impossible:
treat page content as untrusted whatever the model is told.

## Security limits

The policy checks the URL as written. It does not resolve DNS, so a public name
that resolves to a private address is not refused here, and it does not see
redirects, subresources or anything the page loads. Your engine must enforce
those itself, ideally in an isolated network namespace behind an egress proxy.

## Parity

prism-parity's `browser-url-policy` corpus pins the URL policy against the PHP
reference and the TypeScript port.

## License

MIT. See [LICENSE](LICENSE).
