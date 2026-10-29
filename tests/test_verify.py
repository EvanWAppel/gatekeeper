"""Every way a Cloudflare Access token can be wrong must come back as None (→ demo)."""

from __future__ import annotations

import base64
import json
import time

import pytest

from gatekeeper import AccessVerifier, Identity

from .conftest import AUD, TEAM

HEADER = "Cf-Access-Jwt-Assertion"


@pytest.fixture
def verifier(fetched):
    return AccessVerifier(team_domain=TEAM, audience=AUD)


# --- the one way in ---------------------------------------------------------


def test_valid_token_returns_identity(verifier, make_token):
    ident = verifier.verify(make_token())
    assert ident == Identity(email="someone@example.com", subject="user-123")


def test_from_headers_reads_the_access_header_case_insensitively(verifier, make_token):
    assert verifier.from_headers({HEADER.lower(): make_token()}) is not None
    assert verifier.from_headers({HEADER: make_token()}) is not None


def test_aud_as_plain_string_is_accepted(verifier, make_token):
    assert verifier.verify(make_token(aud=AUD)) is not None


# --- everything else is None ------------------------------------------------


@pytest.mark.parametrize("token", [None, "", "   ", "not-a-jwt", "a.b.c"])
def test_missing_or_garbage_token(verifier, token):
    assert verifier.verify(token) is None


def test_missing_header(verifier):
    assert verifier.from_headers({}) is None
    assert verifier.from_headers(None) is None


def test_signed_by_another_key_with_the_same_kid(verifier, make_token, attacker_key):
    assert verifier.verify(make_token(key=attacker_key[0])) is None


def test_unknown_kid(verifier, make_token):
    assert verifier.verify(make_token(kid="not-a-team-key")) is None


def test_wrong_audience(verifier, make_token):
    assert verifier.verify(make_token(aud=["some-other-app"])) is None


def test_missing_audience(verifier, make_token):
    assert verifier.verify(make_token(aud=None)) is None


def test_wrong_issuer(verifier, make_token):
    assert verifier.verify(make_token(iss="https://evil.cloudflareaccess.com")) is None


def test_missing_issuer(verifier, make_token):
    assert verifier.verify(make_token(iss=None)) is None


def test_expired(verifier, make_token):
    past = int(time.time()) - 7200
    assert verifier.verify(make_token(iat=past, nbf=past, exp=past + 60)) is None


def test_missing_expiry(verifier, make_token):
    assert verifier.verify(make_token(exp=None)) is None


def test_not_yet_valid(verifier, make_token):
    future = int(time.time()) + 7200
    assert verifier.verify(make_token(nbf=future, exp=future + 3600)) is None


def test_missing_email(verifier, make_token):
    # Service tokens carry no email; they never get the full app.
    assert verifier.verify(make_token(email=None)) is None


def test_alg_none(verifier, make_token):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    now = int(time.time())
    claims = {"aud": [AUD], "iss": TEAM, "email": "x@example.com", "exp": now + 3600, "nbf": now}
    forged = f"{b64({'alg': 'none', 'kid': 'team-key-1'})}.{b64(claims)}."
    assert verifier.verify(forged) is None


def test_hs256_signed_with_the_public_key(verifier, team_key):
    # Algorithm confusion: an HMAC token keyed with the (public) RSA key material, built by
    # hand because PyJWT refuses to sign one — an attacker wouldn't use PyJWT.
    import hashlib
    import hmac

    from cryptography.hazmat.primitives import serialization

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    pem = team_key[0].public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = int(time.time())
    claims = {"aud": [AUD], "iss": TEAM, "email": "x@example.com", "exp": now + 3600, "nbf": now}
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "team-key-1"}).encode())
    body = b64(json.dumps(claims).encode())
    sig = b64(hmac.new(pem, f"{head}.{body}".encode(), hashlib.sha256).digest())
    assert verifier.verify(f"{head}.{body}.{sig}") is None


def test_keys_are_fetched_only_from_the_configured_team(verifier, make_token, fetched):
    # A token naming its own key location (jku / x5u) must not redirect the fetch.
    token = make_token(headers={"jku": "https://evil.example/certs", "x5u": "https://evil.example/x"})
    verifier.verify(token)
    assert fetched["calls"]
    assert set(fetched["calls"]) == {f"{TEAM}/cdn-cgi/access/certs"}


def test_key_fetch_failure_is_none_not_an_exception(verifier, make_token, fetched):
    fetched["state"]["fail"] = True
    assert verifier.verify(make_token()) is None


# --- misconfiguration is loud, at startup ------------------------------------


@pytest.mark.parametrize(
    "team",
    [
        "",
        "http://example-team.cloudflareaccess.com",
        "https://example-team.cloudflareaccess.com.evil.com",
        "https://evil.com",
        "example-team.cloudflareaccess.com",
        "https://example-team.cloudflareaccess.com/path",
    ],
)
def test_bad_team_domain_raises(team):
    with pytest.raises(ValueError):
        AccessVerifier(team_domain=team, audience=AUD)


def test_trailing_slash_on_team_domain_is_normalised(fetched, make_token):
    v = AccessVerifier(team_domain=TEAM + "/", audience=AUD)
    assert v.verify(make_token()) is not None


@pytest.mark.parametrize("aud", ["", "   ", None])
def test_empty_audience_raises(aud):
    with pytest.raises(ValueError):
        AccessVerifier(team_domain=TEAM, audience=aud)


# --- review fixes (2026-10-22) -----------------------------------------------


def test_rotated_out_key_stops_working_once_the_key_set_refreshes(monkeypatch, team_key, make_token):
    # Finding 1: a per-kid cache must not outlive Cloudflare dropping that key.
    import jwt as pyjwt

    from .conftest import _keypair

    served = {"keys": [team_key[1]]}
    monkeypatch.setattr(pyjwt.PyJWKClient, "fetch_data", lambda self: served)
    v = AccessVerifier(team_domain=TEAM, audience=AUD, key_cache_seconds=0.05)
    assert v.verify(make_token()) is not None

    served = {"keys": [_keypair("team-key-2")[1]]}  # Cloudflare rotated team-key-1 out
    monkeypatch.setattr(pyjwt.PyJWKClient, "fetch_data", lambda self: served)
    time.sleep(0.1)
    assert v.verify(make_token()) is None


def test_random_kids_do_not_trigger_a_fetch_each(verifier, make_token, fetched):
    # Finding 2: an attacker spraying unknown kids must not turn every request into a fetch.
    verifier.verify(make_token())
    before = len(fetched["calls"])
    for i in range(50):
        verifier.verify(make_token(kid=f"random-{i}"))
    assert len(fetched["calls"]) - before <= 1


def test_key_fetch_has_a_short_timeout(verifier):
    assert verifier._keys.timeout <= 5


def test_unexpected_errors_inside_verification_return_none(verifier):
    # Finding 3: "never raises" holds even for errors PyJWT doesn't wrap.
    assert verifier.verify("a\ud800.b.c") is None


def test_non_string_header_names_are_skipped(verifier, make_token):
    assert verifier.from_headers({1: "x", HEADER: make_token()}) is not None


@pytest.mark.parametrize("leeway", [-1, 301, 10**9])
def test_out_of_range_leeway_raises(leeway):
    # Finding 6: a huge leeway would accept long-expired tokens.
    with pytest.raises(ValueError):
        AccessVerifier(team_domain=TEAM, audience=AUD, leeway_seconds=leeway)


@pytest.mark.parametrize("seconds", [0, -5])
def test_non_positive_key_cache_raises(seconds):
    with pytest.raises(ValueError):
        AccessVerifier(team_domain=TEAM, audience=AUD, key_cache_seconds=seconds)


def test_dependency_floor_is_the_tested_pyjwt():
    # Finding 2: apps resolve PyJWT themselves, so the floor (not our lock) protects them.
    import tomllib
    from pathlib import Path

    deps = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())["project"]["dependencies"]
    assert any(d.replace(" ", "").startswith("pyjwt[crypto]>=2.15.1") for d in deps)


# --- startup self-check: make "everyone gets the demo" visible ----------------


def test_check_passes_when_team_keys_load(verifier):
    verifier.check()


def test_check_raises_when_keys_cannot_be_fetched(verifier, fetched):
    fetched["state"]["fail"] = True
    with pytest.raises(RuntimeError, match="keys"):
        verifier.check()


def test_check_raises_when_key_set_has_no_usable_keys(monkeypatch):
    import jwt as pyjwt

    monkeypatch.setattr(pyjwt.PyJWKClient, "fetch_data", lambda self: {"keys": []})
    v = AccessVerifier(team_domain=TEAM, audience=AUD)
    with pytest.raises(RuntimeError):
        v.check()


# --- check() wraps every failure (homestar#41 review, MEDIUM; _system EA-8) ---------


def _serve_body(monkeypatch, body: bytes):
    """Drive PyJWT's real fetch path, but answer the certs request with ``body`` (200)."""
    import io

    import jwt.jwks_client as jc

    class Opener:
        def open(self, request, timeout=None):
            return io.BytesIO(body)

    monkeypatch.setattr(jc.urllib.request, "build_opener", lambda *handlers: Opener())


def test_check_wraps_a_non_json_200_as_runtime_error(monkeypatch):
    _serve_body(monkeypatch, b"<html>Cloudflare login page</html>")
    v = AccessVerifier(team_domain=TEAM, audience=AUD)
    with pytest.raises(RuntimeError, match="signing keys"):
        v.check()


def test_check_wraps_any_unexpected_error_as_runtime_error(monkeypatch):
    import jwt as pyjwt

    def explode(self):
        raise KeyError("surprise")

    monkeypatch.setattr(pyjwt.PyJWKClient, "fetch_data", explode)
    v = AccessVerifier(team_domain=TEAM, audience=AUD)
    with pytest.raises(RuntimeError, match="signing keys") as info:
        v.check()
    assert isinstance(info.value.__cause__, KeyError)  # original kept for debugging


def test_verify_with_a_non_json_200_is_none(monkeypatch, make_token):
    _serve_body(monkeypatch, b"<html>not keys</html>")
    v = AccessVerifier(team_domain=TEAM, audience=AUD)
    assert v.verify(make_token()) is None
