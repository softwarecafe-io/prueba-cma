"""Slice: validación de JWT + contexto RLS por transacción.

Implementación autocontenida del contrato
`contrato/auth-jwt-rls.md` (§1.1 invariantes + §2 JWT + §3 contexto RLS).

Solo datos sintéticos. Sin Cognito ni BD reales: el JWKS y la conexión se
simulan en las pruebas.
"""

from .settings import AuthSettings
from .jwks import JWKSClient, SigningKeyNotFoundError
from .jwt_validator import InvalidAccessToken, validate_access_token
from .db import RecordingConnection
from .app import create_app

__all__ = [
    "AuthSettings",
    "JWKSClient",
    "SigningKeyNotFoundError",
    "InvalidAccessToken",
    "validate_access_token",
    "RecordingConnection",
    "create_app",
]
