"""Fixtures de prueba: llaves RS256 sintéticas, JWKS simulado y token factory.

Todo es sintético y se genera en el sandbox. Nunca PHI ni secretos reales.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from auth_jwt_rls import (
    AuthSettings,
    JWKSClient,
    RecordingConnection,
    create_app,
)

# --- Valores sintéticos del "user pool" simulado ---------------------------
ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TESTPOOL"
AUDIENCE = "test-client-id-0001"
PRIMARY_KID = "test-key-1"


def _new_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _public_jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return jwk


@dataclass
class KeyMaterial:
    """Par de llaves de la prueba: la confiable y una "atacante"."""

    primary_private: rsa.RSAPrivateKey
    attacker_private: rsa.RSAPrivateKey
    jwks: dict[str, Any]


@pytest.fixture(scope="session")
def key_material() -> KeyMaterial:
    primary = _new_rsa_key()
    attacker = _new_rsa_key()  # NO está en el JWKS publicado.
    jwks = {"keys": [_public_jwk(primary, PRIMARY_KID)]}
    return KeyMaterial(primary_private=primary, attacker_private=attacker, jwks=jwks)


@pytest.fixture
def settings() -> AuthSettings:
    return AuthSettings(issuer=ISSUER, audience=AUDIENCE, token_use="access")


@pytest.fixture
def jwks_client(key_material: KeyMaterial) -> JWKSClient:
    return JWKSClient(key_material.jwks)


@pytest.fixture
def connection() -> RecordingConnection:
    # Rol de app SIN BYPASSRLS/SUPERUSER (validado en __post_init__).
    return RecordingConnection()


@pytest.fixture
def app(settings, jwks_client, connection):
    return create_app(settings=settings, jwks_client=jwks_client, connection=connection)


@pytest.fixture
def client(app) -> TestClient:
    # raise_server_exceptions=True por defecto; queremos respuestas HTTP reales.
    return TestClient(app)


# --- Token factory ----------------------------------------------------------
TokenFactory = Callable[..., str]


@pytest.fixture
def make_token(key_material: KeyMaterial) -> TokenFactory:
    """Genera un access token sintético firmado, con overrides opcionales.

    Parámetros:
      claims:   dict de overrides/eliminaciones (valor None elimina el claim).
      sign_key: llave privada para firmar (por defecto, la confiable).
      kid:      `kid` del header (por defecto, PRIMARY_KID).
    """

    def _make(
        *,
        claims: dict[str, Any] | None = None,
        sign_key: rsa.RSAPrivateKey | None = None,
        kid: str = PRIMARY_KID,
    ) -> str:
        now = int(time.time())
        payload: dict[str, Any] = {
            "sub": str(uuid.uuid4()),
            "email": "doctor@example.test",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "token_use": "access",
            "custom:tenant_id": str(uuid.uuid4()),
            "custom:membership_id": str(uuid.uuid4()),
            "custom:roles": "admin,doctor",
            "iat": now,
            "exp": now + 3600,
        }
        for key, value in (claims or {}).items():
            if value is None:
                payload.pop(key, None)
            else:
                payload[key] = value
        signing_key = sign_key or key_material.primary_private
        return jwt.encode(payload, signing_key, algorithm="RS256", headers={"kid": kid})

    return _make
