"""Verify Cloudflare Access tokens, so an app can tell a signed-in visitor from everyone else.

Cloudflare Access puts a signed JWT in the ``Cf-Access-Jwt-Assertion`` header of every
request it lets through. ``AccessVerifier.verify`` returns an ``Identity`` only for a token
that is signed by your team's current keys, issued by your team, meant for this app, and in
date. Every other case returns ``None`` — so an app that shows its full version only when it
gets an ``Identity`` fails toward its public version, never toward the private one.

Configuration (team domain, the app's AUD tag) is passed in by each app; none lives here.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass

import jwt

__all__ = ["HEADER", "AccessVerifier", "Identity"]

log = logging.getLogger(__name__)

HEADER = "Cf-Access-Jwt-Assertion"

# https://<team>.cloudflareaccess.com — nothing before, nothing after.
_TEAM_DOMAIN = re.compile(r"https://[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.cloudflareaccess\.com")

# Cloudflare signs Access tokens with RS256. Accepting anything else invites
# algorithm-confusion and "alg: none" forgeries.
_ALGORITHMS = ["RS256"]


@dataclass(frozen=True)
class Identity:
    email: str
    subject: str


class AccessVerifier:
    """Checks Access tokens for one app.

    ``team_domain``: ``https://<team>.cloudflareaccess.com`` (Zero Trust → Settings).
    ``audience``: the app's Application Audience (AUD) tag (Access → the app → Overview).

    Bad configuration raises ``ValueError`` here, at startup, so it is loud; bad tokens
    never raise from ``verify`` — they return ``None``.
    """

    def __init__(
        self,
        team_domain: str,
        audience: str,
        *,
        leeway_seconds: int = 60,
        key_cache_seconds: float = 3600,
    ) -> None:
        team = (team_domain or "").strip().rstrip("/").lower()
        if not _TEAM_DOMAIN.fullmatch(team):
            raise ValueError(
                "team_domain must look like https://<team>.cloudflareaccess.com "
                f"(got {team_domain!r})"
            )
        aud = (audience or "").strip()
        if not aud:
            raise ValueError("audience (the app's Access AUD tag) is required")
        if not 0 <= leeway_seconds <= 300:
            raise ValueError(f"leeway_seconds must be 0–300 (got {leeway_seconds!r})")
        if not key_cache_seconds > 0:
            raise ValueError(f"key_cache_seconds must be positive (got {key_cache_seconds!r})")

        self._issuer = team
        self._audience = aud
        self._leeway = leeway_seconds
        # Keys come only from the configured team, never from anything the token says
        # (its jku / x5u headers are ignored). Only the whole key set is cached, so a key
        # Cloudflare rotates out stops working on the next refresh (cache_keys=True would
        # keep it per-kid for the life of the process). Unknown kids refetch at most once
        # per cooldown, and a slow Cloudflare can't hold a request for long.
        self._keys = jwt.PyJWKClient(
            f"{team}/cdn-cgi/access/certs",
            cache_keys=False,
            cache_jwk_set=True,
            lifespan=key_cache_seconds,
            cooldown_duration=30,
            timeout=5,
        )

    def check(self) -> None:
        """Startup self-check: raise ``RuntimeError`` if the team's signing keys can't be
        loaded and used. Without this, a broken environment looks exactly like "nobody is
        signed in" — every visitor quietly gets the public version. Call it once at startup
        and log (or alert on) the error.
        """
        try:
            keys = self._keys.get_signing_keys(refresh=True)
        except jwt.PyJWTError as exc:
            raise RuntimeError(f"cannot load Cloudflare Access signing keys: {exc}") from exc
        if not keys:
            raise RuntimeError("Cloudflare Access returned no usable signing keys")

    def verify(self, token: str | None) -> Identity | None:
        """The signed-in identity for a valid token, else ``None``."""
        if not isinstance(token, str) or not token.strip():
            return None
        try:
            signing_key = self._keys.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=_ALGORITHMS,
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            # Never log the token itself.
            log.info("Access token rejected: %s", type(exc).__name__)
            return None
        except Exception as exc:  # noqa: BLE001 — fail toward the public version, loudly
            log.warning("Access token check failed unexpectedly: %s", type(exc).__name__)
            return None

        email = claims.get("email")
        if not isinstance(email, str) or not email:
            log.info("Access token rejected: no email claim (service token?)")
            return None
        return Identity(email=email, subject=str(claims.get("sub", "")))

    def from_headers(self, headers: Mapping[str, str] | None) -> Identity | None:
        """``verify`` the Access header from a request's headers (any letter case)."""
        if not headers:
            return None
        wanted = HEADER.lower()
        for name, value in headers.items():
            if isinstance(name, str) and name.lower() == wanted:
                return self.verify(value)
        return None
