# auth-jwt-rls — slice de validación JWT + contexto RLS

Recorte autocontenido del contrato `SPEC-api-auth-usuarios` (v1.1), limitado a
**§1.1 invariantes + §2 JWT + §3 contexto RLS**. Implementa, en **Python
(FastAPI + Pydantic)**:

1. **Validador de JWT** (`auth_jwt_rls/jwt_validator.py`): verifica firma RS256
   contra un **JWKS**, `exp`, `iss`, `aud`/`client_id` y `token_use`. Token
   inválido o expirado → **401, sin tocar BD**.
2. **Contexto RLS por transacción** (`auth_jwt_rls/rls.py`): traduce el token
   validado a tres `SET LOCAL` (`app.current_tenant_id`, `app.current_user_id`,
   `app.current_role_set`) dentro de la transacción de la request. Al cerrar la
   transacción, `SET LOCAL` se resetea solo (sin fuga entre requests).
3. **Endpoints** (`auth_jwt_rls/app.py`): `GET /ping-tenant` (protegido) y
   `GET /health` (público, sin contexto).

No se usa Cognito ni BD reales:

* El **JWKS** se simula con un par de llaves **RS256** de prueba
  (`tests/conftest.py`).
* La conexión es un **doble** (`auth_jwt_rls/db.py`) que registra los
  `SET LOCAL` y se construye **sin** `BYPASSRLS`/`SUPERUSER`.

Todos los datos son **sintéticos**. Nunca PHI ni secretos reales.

## Cómo correr los tests

```bash
cd auth-jwt-rls
python -m pip install -r requirements.txt
python -m pytest
```

Salida esperada: **9 checks verdes** (más la variante parametrizada de C4).

## Mapeo checks C1–C9 → tests (`tests/test_checks.py`)

| Check | Qué verifica | Test |
|-------|--------------|------|
| **C1** | Token válido → `/ping-tenant` 200; contexto sale del token | `test_c1_valid_token_pings_tenant_with_context_from_token` |
| **C2** | Firma inválida → 401, sin `SET LOCAL` (no se tocó BD) | `test_c2_invalid_signature_is_401_without_touching_db` |
| **C3** | Token expirado → 401, sin contexto | `test_c3_expired_token_is_401_without_context` |
| **C4** | `iss`/`aud` incorrecto → 401 | `test_c4_wrong_iss_or_aud_is_401` |
| **C5** | `token_use` inesperado → 401 | `test_c5_wrong_token_use_is_401` |
| **C6** | `SET LOCAL` usa el `custom:tenant_id` del token; `X-Tenant-Id` se ignora | `test_c6_tenant_comes_from_token_not_from_header` |
| **C7** | El contexto no se hereda entre requests en la misma conexión | `test_c7_context_does_not_leak_between_requests` |
| **C8** | `/health` 200 sin abrir contexto RLS | `test_c8_health_runs_without_rls_context` |
| **C9** | El rol de BD se configura sin `BYPASSRLS` | `test_c9_app_db_role_has_no_bypass_rls` |
