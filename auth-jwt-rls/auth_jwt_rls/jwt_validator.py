"""Validador de access tokens (contrato §2).

Verifica, en cada request: firma RS256 contra el JWKS, `exp`, `iss`, `aud` y
`token_use`. Cualquier fallo levanta `InvalidAccessToken`, que la capa HTTP
traduce a 401 SIN tocar la base de datos.
"""

from __future__ import annotations

from typing import Any

import jwt

from .jwks import JWKSClient, SigningKeyNotFoundError
from .settings import AuthSettings

# Claim que transporta el tenant ACTIVO de la sesión (firmado, vinculante).
TENANT_CLAIM = "custom:tenant_id"
# Claims requeridos por el contrato para construir el contexto RLS.
_REQUIRED_CLAIMS = ("exp", "iss", "aud", "sub", TENANT_CLAIM)


class InvalidAccessToken(Exception):
    """Token ausente, mal formado, con firma inválida o claims incorrectos."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def validate_access_token(
    token: str,
    jwks_client: JWKSClient,
    settings: AuthSettings,
) -> dict[str, Any]:
    """Valida el token y devuelve sus claims, o lanza `InvalidAccessToken`.

    No realiza ningún acceso a BD: la validación es puramente criptográfica y
    de claims, de modo que un token inválido nunca abre transacción (I1/§3.4).
    """
    if not token:
        raise InvalidAccessToken("missing token")

    # 1) Header sin verificar: solo para resolver el `kid` -> llave pública.
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise InvalidAccessToken(f"malformed token header: {exc}") from exc

    try:
        signing_key = jwks_client.get_signing_key(header.get("kid"))
    except SigningKeyNotFoundError as exc:
        raise InvalidAccessToken("unknown signing key") from exc

    # 2) Verifica firma + claims estándar (exp, iss, aud) de un solo paso.
    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=list(settings.algorithms),
            audience=settings.audience,
            issuer=settings.issuer,
            options={"require": list(_REQUIRED_CLAIMS)},
        )
    except jwt.PyJWTError as exc:
        # Cubre firma inválida, expirado, iss/aud incorrectos, etc.
        raise InvalidAccessToken(f"token rejected: {exc}") from exc

    # 3) token_use: debe ser el access token (no id/refresh).
    if claims.get("token_use") != settings.token_use:
        raise InvalidAccessToken("unexpected token_use")

    return claims
