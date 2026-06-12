"""Doble de conexión que registra los `SET LOCAL` (contrato §3).

Reemplaza a una conexión PostgreSQL real para las pruebas. Modela dos hechos
del contrato:

* Cada request corre dentro de una transacción y configura el contexto RLS con
  `SET LOCAL`. Al cerrar la transacción, `SET LOCAL` se resetea solo: no hay
  fuga entre requests aunque la conexión del pool se reutilice (§3.3, C7).
* El rol PostgreSQL de la app NO tiene `BYPASSRLS` ni `SUPERUSER` (§3.4, C9).
  Construir la conexión con cualquiera de esos flags es un error de
  configuración y se rechaza.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

# Rol de aplicación por defecto. Documentado como SIN privilegios que se salten
# RLS: si faltara un SET LOCAL, las políticas devuelven 0 filas (falla segura).
DEFAULT_APP_ROLE = "amed_app_rls"


@dataclass
class RecordingConnection:
    """Conexión simulada que registra cada `SET LOCAL` ejecutado.

    Atributos de auditoría:
      * ``set_local_log``: todos los (clave, valor) de SET LOCAL en la vida de
        la conexión (vacío => no se tocó el contexto RLS).
      * ``transactions``: snapshot del contexto local al cerrar cada
        transacción, para verificar el no-arrastre entre requests.
    """

    role: str = DEFAULT_APP_ROLE
    # Privilegios del rol de BD. El contrato exige que sean False.
    has_bypass_rls: bool = False
    is_superuser: bool = False

    executed: list[str] = field(default_factory=list)
    set_local_log: list[tuple[str, str]] = field(default_factory=list)
    transactions: list[dict[str, str]] = field(default_factory=list)
    local_settings: dict[str, str] = field(default_factory=dict)
    _in_transaction: bool = False

    def __post_init__(self) -> None:
        # C9: el rol de la app no puede saltarse RLS.
        if self.has_bypass_rls or self.is_superuser:
            raise ValueError(
                "El rol de BD de la app NO debe tener BYPASSRLS ni SUPERUSER "
                "(contrato §3.4 / C9)."
            )

    @contextmanager
    def transaction(self) -> Iterator["RecordingConnection"]:
        """Abre una transacción. Al salir, `SET LOCAL` se resetea (como en PG)."""
        if self._in_transaction:
            raise RuntimeError("transacción anidada no soportada en el doble")
        self._in_transaction = True
        self.local_settings = {}
        self.executed.append("BEGIN")
        try:
            yield self
            self.executed.append("COMMIT")
        finally:
            # Snapshot de lo que estuvo activo en esta transacción, y reset.
            self.transactions.append(dict(self.local_settings))
            self.local_settings = {}
            self._in_transaction = False

    def set_local(self, key: str, value: str) -> None:
        """Ejecuta `SET LOCAL <key> = '<value>'` dentro de la transacción."""
        if not self._in_transaction:
            raise RuntimeError("SET LOCAL fuera de una transacción")
        statement = f"SET LOCAL {key} = '{value}'"
        self.executed.append(statement)
        self.set_local_log.append((key, value))
        self.local_settings[key] = value
