"""Configuración del validador de JWT.

Valores que la API debe verificar en cada request (contrato §2):
firma (vía JWKS), `exp`, `iss` (el user pool), `aud`/`client_id` y `token_use`.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AuthSettings(BaseModel):
    """Parámetros del contrato de identidad (§2).

    En producción saldrían del entorno; aquí se inyectan para poder simular el
    user pool de Cognito con valores sintéticos.
    """

    # `iss` esperado: la URL del User Pool de Cognito.
    issuer: str = Field(..., description="iss esperado (URL del user pool)")
    # `aud` / `client_id` esperado del access token.
    audience: str = Field(..., description="aud/client_id esperado")
    # Cognito marca los access tokens con token_use == 'access'.
    token_use: str = Field("access", description="token_use esperado")
    # Solo RS256: tokens firmados asimétricamente y validados contra el JWKS.
    algorithms: tuple[str, ...] = Field(default=("RS256",))
