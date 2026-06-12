"""App FastAPI con el endpoint protegido y el público (contrato §1, §3.5)."""

from __future__ import annotations

from fastapi import Depends, FastAPI

from .db import RecordingConnection
from .jwks import JWKSClient
from .rls import RLSContext, require_rls_context
from .settings import AuthSettings


def create_app(
    *,
    settings: AuthSettings,
    jwks_client: JWKSClient,
    connection: RecordingConnection,
) -> FastAPI:
    """Construye la app inyectando configuración, JWKS y conexión simulada.

    La inyección por parámetros permite a las pruebas usar un par de llaves
    RS256 de prueba y una conexión que registra los `SET LOCAL`.
    """
    app = FastAPI(title="auth-jwt-rls slice")
    app.state.settings = settings
    app.state.jwks_client = jwks_client
    app.state.connection = connection

    @app.get("/health")
    def health() -> dict[str, str]:
        # Público: corre SIN contexto RLS y no consulta tablas de tenant (§3.5).
        return {"status": "ok"}

    @app.get("/ping-tenant")
    def ping_tenant(ctx: RLSContext = Depends(require_rls_context)) -> dict[str, str]:
        # Protegido: ejercita token -> validación -> contexto -> respuesta.
        return {
            "tenant_id": ctx.tenant_id,
            "user_id": ctx.user_id,
            "roles": ctx.roles,
        }

    return app
