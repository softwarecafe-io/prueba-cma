"""Cliente JWKS (simulado).

En producción el JWKS se descarga del endpoint público del User Pool de
Cognito (`/.well-known/jwks.json`) y se cachea. Aquí recibe el documento JWKS
ya materializado para no levantar infraestructura: el contrato pide simularlo
con un par de llaves RS256 de prueba.
"""

from __future__ import annotations

import json
from typing import Any

import jwt
from jwt.algorithms import RSAAlgorithm


class SigningKeyNotFoundError(Exception):
    """No hay en el JWKS una llave con el `kid` del header del token."""

    def __init__(self, kid: str | None) -> None:
        super().__init__(f"No signing key found for kid={kid!r}")
        self.kid = kid


class JWKSClient:
    """Resuelve la llave pública de firma a partir del `kid` del token."""

    def __init__(self, jwks: dict[str, Any]) -> None:
        self._public_keys: dict[str, Any] = {}
        for jwk in jwks.get("keys", []):
            kid = jwk.get("kid")
            if not kid:
                continue
            # from_jwk devuelve un objeto de llave pública de `cryptography`.
            self._public_keys[kid] = RSAAlgorithm.from_jwk(json.dumps(jwk))

    def get_signing_key(self, kid: str | None) -> Any:
        """Devuelve la llave pública para `kid` o lanza si no existe."""
        key = self._public_keys.get(kid) if kid else None
        if key is None:
            raise SigningKeyNotFoundError(kid)
        return key
