"""Contexto RLS por transacción — el puente crítico (contrato §3).

Implementa el "middleware" de contexto como una dependencia de FastAPI: es la
forma idiomática de envolver cada request protegida en una transacción y
garantizar el reset al terminar.

Flujo (§3):
  1. Valida el JWT (§2). Si falla -> 401 SIN abrir transacción (no se toca BD).
  2. Extrae `tenant_id := custom:tenant_id` y `user_id := sub` DEL TOKEN
     (invariante I1: jamás del body ni de un header crudo).
  3. Abre la transacción de la request y ejecuta, dentro de ella, los tres
     `SET LOCAL` del contrato.
  4. Al cerrar la transacción, `SET LOCAL` se resetea solo (sin fuga, C7).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from fastapi import HTTPException, Request, status

from .jwt_validator import TENANT_CLAIM, InvalidAccessToken, validate_access_token

# Claves de configuración de sesión de PostgreSQL para las políticas RLS.
TENANT_SETTING = "app.current_tenant_id"
USER_SETTING = "app.current_user_id"
ROLE_SET_SETTING = "app.current_role_set"


@dataclass(frozen=True)
class RLSContext:
    """Contexto derivado del token validado y aplicado a la transacción."""

    tenant_id: str
    user_id: str
    roles: str


def _extract_bearer(authorization: str | None) -> str:
    """Obtiene el token del header `Authorization: Bearer <token>`."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token.strip()


def require_rls_context(request: Request) -> Iterator[RLSContext]:
    """Dependencia: valida el token y monta el contexto RLS de la transacción.

    Nota de seguridad (I1): el `tenant_id` proviene EXCLUSIVAMENTE del claim
    firmado `custom:tenant_id`. Un header como `X-Tenant-Id` se ignora por
    completo (C6).
    """
    settings = request.app.state.settings
    jwks_client = request.app.state.jwks_client
    connection = request.app.state.connection

    # 1) Validación del JWT — ocurre ANTES de abrir cualquier transacción.
    token = _extract_bearer(request.headers.get("Authorization"))
    try:
        claims = validate_access_token(token, jwks_client, settings)
    except InvalidAccessToken as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token: {exc.reason}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    # 2) Identidad SIEMPRE desde el token validado (I1).
    tenant_id = str(claims[TENANT_CLAIM])
    user_id = str(claims["sub"])
    roles = str(claims.get("custom:roles", ""))

    # 3) Transacción + SET LOCAL. 4) Reset automático al salir del `with`.
    with connection.transaction() as tx:
        tx.set_local(TENANT_SETTING, tenant_id)
        tx.set_local(USER_SETTING, user_id)
        tx.set_local(ROLE_SET_SETTING, roles)
        yield RLSContext(tenant_id=tenant_id, user_id=user_id, roles=roles)
