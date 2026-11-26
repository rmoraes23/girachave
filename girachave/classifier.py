"""Classificação heurística de contas: serviço, genérica, terceiro ou pessoal.

O Entra ID não diferencia nativamente esses tipos — essa é justamente a
lacuna que o Girachave cobre. As regras são conservadoras e podem ser
estendidas com padrões próprios da empresa (``extra_patterns``).
"""
from __future__ import annotations

import re
import unicodedata

from .models import Account, AccountKind

SERVICE_PREFIX = re.compile(
    r"^(svc|sa|srv|service|servico|app|bot|sql|backup|bkp|sync|scan|integra(cao)?|api|job|task|robo|rpa)[-_.]",
    re.IGNORECASE,
)
SERVICE_WORDS = {"service", "servico", "integracao", "robo", "rpa", "automacao", "daemon", "backup"}

GENERIC_WORDS = {
    "admin", "administrador", "administrator", "ti", "it", "suporte", "support", "helpdesk",
    "recepcao", "financeiro", "compras", "rh", "sala", "treinamento", "teste", "test", "temp",
    "temporario", "generico", "generica", "shared", "compartilhado", "compartilhada",
    "impressora", "scanner", "portaria", "estoque", "contabilidade", "fiscal", "comercial",
    "atendimento", "noreply", "no-reply", "contato", "sac", "kiosk", "quiosque", "loja",
}

EXTERNAL_WORDS = {
    "fornecedor", "terceiro", "terceirizado", "terceirizada", "vendor", "ext", "externo",
    "parceiro", "partner", "consultor", "consultoria", "contractor", "prestador",
}


NON_PERSONAL_HINT = {AccountKind.SERVICE, AccountKind.GENERIC, AccountKind.EXTERNAL}


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return text.lower()


def _tokens(*parts: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", _normalize(" ".join(parts))) if t}


def classify(account: Account, extra_patterns: dict[str, list[str]] | None = None) -> AccountKind:
    upn = account.upn.lower()
    local = upn.split("@", 1)[0]
    # Departamento só conta para identificar terceiros: "TI" ou "Financeiro" no
    # departamento de uma pessoa não torna a conta dela genérica.
    tokens = _tokens(local, account.display_name)
    dept = _tokens(account.department)

    if extra_patterns:
        for kind_value, patterns in extra_patterns.items():
            for pat in patterns:
                if re.search(pat, upn, re.IGNORECASE):
                    return AccountKind(kind_value)

    # Convidados B2B e contas marcadas como externas
    if account.user_type.lower() == "guest" or "#ext#" in upn or (tokens | dept) & EXTERNAL_WORDS:
        return AccountKind.EXTERNAL

    if SERVICE_PREFIX.match(local) or tokens & SERVICE_WORDS:
        return AccountKind.SERVICE

    if tokens & GENERIC_WORDS:
        return AccountKind.GENERIC

    return AccountKind.PERSONAL


def classify_all(accounts: list[Account], extra_patterns: dict[str, list[str]] | None = None) -> None:
    for acc in accounts:
        acc.kind = classify(acc, extra_patterns)
