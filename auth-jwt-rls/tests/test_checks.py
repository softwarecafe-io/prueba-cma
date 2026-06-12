"""Checks de aceptación C1–C9 del contrato `auth-jwt-rls.md` §4."""

from __future__ import annotations

import uuid

import pytest

from auth_jwt_rls import RecordingConnection
from auth_jwt_rls.rls import ROLE_SET_SETTING, TENANT_SETTING, USER_SETTING


def _set_local_dict(connection: RecordingConnection) -> dict[str, str]:
    """Aplana el log de SET LOCAL a {clave: último_valor}."""
    return dict(connection.set_local_log)


# --- C1 ---------------------------------------------------------------------
def test_c1_valid_token_pings_tenant_with_context_from_token(client, make_token, connection):
    tenant_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    token = make_token(claims={"sub": user_id, "custom:tenant_id": tenant_id})

    resp = client.get("/ping-tenant", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    body = resp.json()
    # El contexto proviene del token.
    assert body["tenant_id"] == tenant_id
    assert body["user_id"] == user_id

    settings = _set_local_dict(connection)
    assert settings[TENANT_SETTING] == tenant_id
    assert settings[USER_SETTING] == user_id
    assert ROLE_SET_SETTING in settings


# --- C2 ---------------------------------------------------------------------
def test_c2_invalid_signature_is_401_without_touching_db(client, make_token, connection, key_material):
    # Firmado con la llave "atacante", que NO está en el JWKS.
    token = make_token(sign_key=key_material.attacker_private)

    resp = client.get("/ping-tenant", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401
    # No se ejecutó ningún SET LOCAL ni se abrió transacción (no se tocó BD).
    assert connection.set_local_log == []
    assert connection.executed == []


# --- C3 ---------------------------------------------------------------------
def test_c3_expired_token_is_401_without_context(client, make_token, connection):
    token = make_token(claims={"exp": 1_000_000, "iat": 999_000})  # muy en el pasado

    resp = client.get("/ping-tenant", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401
    assert connection.set_local_log == []
    assert connection.executed == []


# --- C4 ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_claims",
    [
        {"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EVILPOOL"},
        {"aud": "some-other-client-id"},
    ],
    ids=["bad_iss", "bad_aud"],
)
def test_c4_wrong_iss_or_aud_is_401(client, make_token, connection, bad_claims):
    token = make_token(claims=bad_claims)

    resp = client.get("/ping-tenant", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401
    assert connection.set_local_log == []


# --- C5 ---------------------------------------------------------------------
def test_c5_wrong_token_use_is_401(client, make_token, connection):
    token = make_token(claims={"token_use": "id"})  # debería ser 'access'

    resp = client.get("/ping-tenant", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401
    assert connection.set_local_log == []


# --- C6 ---------------------------------------------------------------------
def test_c6_tenant_comes_from_token_not_from_header(client, make_token, connection):
    token_tenant = str(uuid.uuid4())
    spoofed_tenant = str(uuid.uuid4())
    token = make_token(claims={"custom:tenant_id": token_tenant})

    resp = client.get(
        "/ping-tenant",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Tenant-Id": spoofed_tenant,  # debe ignorarse
        },
    )

    assert resp.status_code == 200
    settings = _set_local_dict(connection)
    # Gana el del token; el header crudo se ignora (I1).
    assert settings[TENANT_SETTING] == token_tenant
    assert settings[TENANT_SETTING] != spoofed_tenant
    assert resp.json()["tenant_id"] == token_tenant


# --- C7 ---------------------------------------------------------------------
def test_c7_context_does_not_leak_between_requests(client, make_token, connection):
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    token_a = make_token(claims={"custom:tenant_id": tenant_a})
    token_b = make_token(claims={"custom:tenant_id": tenant_b})

    r1 = client.get("/ping-tenant", headers={"Authorization": f"Bearer {token_a}"})
    # Tras cerrar la primera transacción, el contexto local quedó reseteado.
    assert connection.local_settings == {}

    r2 = client.get("/ping-tenant", headers={"Authorization": f"Bearer {token_b}"})

    assert r1.status_code == r2.status_code == 200
    # Dos transacciones independientes; ninguna heredó el tenant de la otra.
    assert len(connection.transactions) == 2
    assert connection.transactions[0][TENANT_SETTING] == tenant_a
    assert connection.transactions[1][TENANT_SETTING] == tenant_b
    assert connection.transactions[1][TENANT_SETTING] != tenant_a
    assert connection.local_settings == {}


# --- C8 ---------------------------------------------------------------------
def test_c8_health_runs_without_rls_context(client, connection):
    resp = client.get("/health")

    assert resp.status_code == 200
    # No se abrió contexto: ni SET LOCAL ni transacción.
    assert connection.set_local_log == []
    assert connection.executed == []


# --- C9 ---------------------------------------------------------------------
def test_c9_app_db_role_has_no_bypass_rls(connection):
    # El doble por defecto se configura sin privilegios que se salten RLS.
    assert connection.has_bypass_rls is False
    assert connection.is_superuser is False

    # Configurarlo con BYPASSRLS o SUPERUSER es un error de configuración.
    with pytest.raises(ValueError):
        RecordingConnection(has_bypass_rls=True)
    with pytest.raises(ValueError):
        RecordingConnection(is_superuser=True)
