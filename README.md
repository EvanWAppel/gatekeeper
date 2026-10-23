# gatekeeper

Verify Cloudflare Access tokens so one deploy can serve **signed-in visitors the full app**
and **everyone else the public demo**.

Cloudflare Access adds a signed JWT (`Cf-Access-Jwt-Assertion`) to every request it lets
through. `AccessVerifier` returns an `Identity` only when that token is:

- signed with **RS256** by a key fetched from **your team's** certs endpoint (any `jku` / `x5u`
  in the token is ignored; `alg: none` and HMAC tokens are rejected; a key Cloudflare rotates
  out stops working on the next key-set refresh, hourly by default),
- issued by your team (`iss`), meant for this app (`aud`), and in date (`exp`, `nbf`),
- carrying an `email` (service tokens are not people).

Everything else — no header, a forged or expired token, Cloudflare unreachable — returns
`None`. Show the full app only on an `Identity`, and every failure lands on the public side.

Bad configuration raises `ValueError` when the verifier is built, so it fails at startup,
not quietly per request.

## Use

Pin an exact commit, so an update can only arrive through a reviewed change in your app:

```toml
dependencies = [
    "gatekeeper @ https://github.com/EvanWAppel/gatekeeper/archive/<commit-sha>.zip",
]
```

```python
import os
from gatekeeper import AccessVerifier

verifier = AccessVerifier(
    team_domain=os.environ["CF_ACCESS_TEAM_DOMAIN"],  # https://<team>.cloudflareaccess.com
    audience=os.environ["CF_ACCESS_AUD"],             # the app's Application Audience tag
)
```

At startup, call `verifier.check()` and log the `RuntimeError` it raises if the team's keys
can't be loaded — otherwise a broken environment looks exactly like "nobody is signed in",
and every visitor quietly gets the public version.

Streamlit (≥ 1.37 exposes request headers):

```python
import streamlit as st

identity = verifier.from_headers(st.context.headers)
if identity:
    full_app(identity.email)
else:
    demo()
```

Any framework: pass the request's headers mapping to `from_headers`, or the header value
to `verify`.

## What this does not do

- **It is not the gate for apps without a public version.** If an app has nothing to show
  anonymous visitors, also close its platform URL (`*.up.railway.app`, `*.vercel.app`) —
  otherwise visitors can skip Cloudflare entirely.
- **It holds no configuration.** Team domain and AUD come from each app's environment; the
  allowlist lives in Cloudflare. A test fails if a real team domain or email lands in this repo.

## Develop

```sh
uv run python -m pytest -q
```
