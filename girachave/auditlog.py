"""Log de auditoria à prova de adulteração (append-only, encadeado por hash).

Cada evento carrega o hash do anterior. Alterar, remover ou reordenar
qualquer linha quebra a cadeia — e ``verify`` aponta exatamente onde.

Se ``GIRACHAVE_LOG_KEY`` estiver definida, o encadeamento usa HMAC-SHA256:
sem a chave, um atacante não consegue recalcular a cadeia inteira para
esconder a adulteração. Segredos nunca são gravados no log.
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path

from .models import utcnow

GENESIS = "0" * 64
FORBIDDEN_KEYS = {"password", "senha", "secret", "client_secret", "token", "access_token"}


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def _digest(payload: bytes, key: bytes | None) -> str:
    if key:
        return hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def _key() -> bytes | None:
    k = os.environ.get("GIRACHAVE_LOG_KEY")
    return k.encode() if k else None


def _scrub(data: dict) -> dict:
    """Defesa em profundidade: impede que um segredo vá parar no log por engano."""
    clean = {}
    for k, v in data.items():
        if k.lower() in FORBIDDEN_KEYS:
            clean[k] = "***"
        elif isinstance(v, dict):
            clean[k] = _scrub(v)
        else:
            clean[k] = v
    return clean


def _actor() -> str:
    try:
        return f"{getpass.getuser()}@{socket.gethostname()}"
    except Exception:  # pragma: no cover
        return "desconhecido"


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _last(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last_line = ""
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last_line = line
        if not last_line:
            return 0, GENESIS
        e = json.loads(last_line)
        return int(e["seq"]), e["hash"]

    def append(self, event: str, data: dict | None = None) -> dict:
        seq, prev = self._last()
        entry = {
            "seq": seq + 1,
            "ts": utcnow().isoformat(timespec="seconds"),
            "actor": _actor(),
            "event": event,
            "data": _scrub(data or {}),
            "prev": prev,
            "alg": "hmac-sha256" if _key() else "sha256",
        }
        entry["hash"] = _digest(_canonical(entry), _key())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    broken_at: int | None = None
    reason: str = ""


def verify(path: str | Path) -> VerifyResult:
    p = Path(path)
    if not p.exists():
        return VerifyResult(False, 0, None, "arquivo não encontrado")
    key = _key()
    prev = GENESIS
    n = 0
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except ValueError:
                return VerifyResult(False, n, lineno, "linha não é JSON válido")
            n += 1
            if e.get("seq") != n:
                return VerifyResult(False, n, lineno, f"sequência esperada {n}, encontrada {e.get('seq')}")
            if e.get("prev") != prev:
                return VerifyResult(False, n, lineno, "encadeamento quebrado (linha removida ou reordenada)")
            if e.get("alg") == "hmac-sha256" and not key:
                return VerifyResult(False, n, lineno, "log usa HMAC: defina GIRACHAVE_LOG_KEY para verificar")
            body = {k: v for k, v in e.items() if k != "hash"}
            expected = _digest(_canonical(body), key if e.get("alg") == "hmac-sha256" else None)
            if not hmac.compare_digest(expected, e.get("hash", "")):
                return VerifyResult(False, n, lineno, "conteúdo alterado (hash não confere)")
            prev = e["hash"]
    return VerifyResult(True, n)
