"""Fixtures: a fake Cloudflare Access team with real RSA keys, no network."""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

TEAM = "https://example-team.cloudflareaccess.com"
AUD = "aud-tag-for-this-app"


def _keypair(kid: str):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return private, jwk


@pytest.fixture(scope="session")
def team_key():
    return _keypair("team-key-1")


@pytest.fixture(scope="session")
def attacker_key():
    return _keypair("team-key-1")  # same kid, different key: a forgery attempt


@pytest.fixture
def fetched(monkeypatch, team_key):
    """Stub the JWKS fetch; record every URL the verifier asks for."""
    calls: list[str] = []
    state = {"fail": False}

    def fake_fetch(self):
        calls.append(self.uri)
        if state["fail"]:
            raise jwt.PyJWKClientConnectionError("network down")
        return {"keys": [team_key[1]]}

    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", fake_fetch)
    return {"calls": calls, "state": state}


@pytest.fixture
def make_token(team_key):
    def make(*, key=None, kid="team-key-1", alg="RS256", headers=None, **claims):
        now = int(time.time())
        payload = {
            "aud": [AUD],
            "iss": TEAM,
            "email": "someone@example.com",
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "sub": "user-123",
        }
        payload.update(claims)
        payload = {k: v for k, v in payload.items() if v is not None}
        signing_key = key if key is not None else team_key[0]
        return jwt.encode(payload, signing_key, algorithm=alg, headers={"kid": kid, **(headers or {})})

    return make
