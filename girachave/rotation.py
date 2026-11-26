"""Rotação segura de senhas de contas de serviço e genéricas.

Princípios:
- *Dry-run* por padrão: nada muda sem ``--apply`` e confirmação explícita.
- Senhas geradas com ``secrets`` (CSPRNG), 32+ caracteres, 4 classes.
- A senha nova só existe em memória e vai direto para o cofre (Azure Key
  Vault). Ela nunca é gravada em disco nem no log de auditoria.
- Contas de terceiros não são rotacionadas: a recomendação é desabilitar
  e revisar — rotacionar mantém um acesso que talvez nem devesse existir.
- Se a entrega no cofre falhar, a senha NÃO é trocada no Entra ID (o cofre
  é gravado primeiro, como nova versão do segredo), evitando lockout.
"""
from __future__ import annotations

import json
import re
import secrets
import string
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime

from .auditlog import AuditLog
from .graph import Credentials, GraphClient, _http, acquire_token
from .models import Account, AccountKind, TenantSnapshot

ROTATABLE = {AccountKind.SERVICE, AccountKind.GENERIC}
SYMBOLS = "!#$%&*+-=?@^_~"
AMBIGUOUS = set("Il1O0")


def generate_password(length: int = 32) -> str:
    if length < 16:
        raise ValueError("comprimento mínimo é 16")
    pools = [
        "".join(c for c in string.ascii_uppercase if c not in AMBIGUOUS),
        "".join(c for c in string.ascii_lowercase if c not in AMBIGUOUS),
        "".join(c for c in string.digits if c not in AMBIGUOUS),
        SYMBOLS,
    ]
    alphabet = "".join(pools)
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(pools))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


@dataclass
class RotationItem:
    account: Account
    reason: str
    warnings: list[str] = field(default_factory=list)


def plan(snapshot: TenantSnapshot, max_age_days: int, now: datetime | None = None,
         only: list[str] | None = None) -> list[RotationItem]:
    now = now or snapshot.collected_at
    only_set = {u.lower() for u in only} if only else None
    items: list[RotationItem] = []
    for acc in snapshot.accounts:
        if only_set is not None and acc.upn.lower() not in only_set:
            continue
        if acc.kind not in ROTATABLE or not acc.enabled:
            continue
        age = None if acc.last_password_change is None else (now - acc.last_password_change).days
        if only_set is None and (age is None or age <= max_age_days):
            continue
        item = RotationItem(acc, f"senha com {age} dias" if age is not None else "rotação solicitada")
        if acc.roles:
            item.warnings.append("conta privilegiada: considere remover o papel em vez de só rotacionar")
        if acc.kind == AccountKind.SERVICE:
            item.warnings.append("atualize a credencial no sistema consumidor (lida do Key Vault) para evitar parada")
        items.append(item)
    return items


def vault_secret_name(upn: str) -> str:
    """Nomes do Key Vault aceitam apenas [0-9a-zA-Z-] e até 127 caracteres."""
    name = re.sub(r"[^0-9a-zA-Z-]", "-", upn.replace("@", "--"))
    return ("girachave-" + name)[:127]


class KeyVaultSink:
    def __init__(self, vault_url: str, creds: Credentials):
        parsed = urllib.parse.urlparse(vault_url)
        if parsed.scheme != "https" or not (parsed.hostname or "").endswith(".vault.azure.net"):
            raise ValueError("vault-url deve ser https://<nome>.vault.azure.net")
        self.base = f"https://{parsed.hostname}"
        self.host = parsed.hostname
        self.token = acquire_token(creds, "https://vault.azure.net/.default")

    def store(self, upn: str, password: str) -> str:
        name = vault_secret_name(upn)
        body = json.dumps({
            "value": password,
            "contentType": "password",
            "tags": {"managed-by": "girachave", "upn": upn[:256]},
        }).encode()
        _, data = _http("PUT", f"{self.base}/secrets/{name}?api-version=7.4",
                        {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
                        body, retries=1, extra_hosts={self.host})
        return data.get("id", name)  # URI da versão — vai para o log (sem o valor)


def execute(items: list[RotationItem], graph: GraphClient | None, sink: KeyVaultSink | None,
            log: AuditLog, simulate: bool = False) -> list[dict]:
    results = []
    for item in items:
        upn = item.account.upn
        password = generate_password()
        try:
            if simulate:
                ref = f"simulado://{vault_secret_name(upn)}"
            else:
                if sink is None or graph is None:
                    raise RuntimeError("cofre não configurado")
                ref = sink.store(upn, password)
                graph.patch(f"/users/{urllib.parse.quote(item.account.id)}", {
                    "passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False}
                })
            entry = log.append("password.rotated", {
                "upn": upn, "account_id": item.account.id, "kind": item.account.kind.value,
                "vault_ref": ref, "reason": item.reason, "simulated": simulate,
            })
            results.append({"upn": upn, "status": "ok", "vault_ref": ref, "log_seq": entry["seq"]})
        except Exception as e:  # registra a falha e segue para a próxima conta
            log.append("password.rotation_failed", {"upn": upn, "error": str(e)[:300], "simulated": simulate})
            results.append({"upn": upn, "status": "erro", "error": str(e)[:300]})
        finally:
            del password
    return results
