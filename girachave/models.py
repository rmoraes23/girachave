"""Modelos de dados do Girachave."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critica"
    HIGH = "alta"
    MEDIUM = "media"
    LOW = "baixa"

    @property
    def weight(self) -> int:
        return {"critica": 15, "alta": 8, "media": 3, "baixa": 1}[self.value]

    @property
    def rank(self) -> int:
        return {"critica": 0, "alta": 1, "media": 2, "baixa": 3}[self.value]

    @property
    def label(self) -> str:
        return {"critica": "Crítica", "alta": "Alta", "media": "Média", "baixa": "Baixa"}[self.value]


class AccountKind(str, Enum):
    SERVICE = "servico"
    GENERIC = "generica"
    EXTERNAL = "terceiro"
    PERSONAL = "pessoal"

    @property
    def label(self) -> str:
        return {
            "servico": "Conta de serviço",
            "generica": "Conta genérica/compartilhada",
            "terceiro": "Conta de terceiro/fornecedor",
            "pessoal": "Conta pessoal",
        }[self.value]


@dataclass
class Account:
    id: str
    upn: str
    display_name: str
    enabled: bool = True
    user_type: str = "Member"
    created: datetime | None = None
    last_password_change: datetime | None = None
    last_sign_in: datetime | None = None
    password_never_expires: bool = False
    mfa_registered: bool | None = None  # None = não foi possível consultar
    mfa_methods: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    has_owner: bool | None = None  # None = não consultado
    department: str = ""
    kind: AccountKind = AccountKind.PERSONAL

    @property
    def privileged(self) -> bool:
        return bool(self.roles)


@dataclass
class AppCredential:
    app_object_id: str
    app_id: str
    app_name: str
    key_id: str
    cred_type: str  # "secret" | "certificate"
    start: datetime | None
    end: datetime | None
    hint: str = ""


@dataclass
class AppPermissionGrant:
    """Permissões de *aplicação* (app-only) concedidas a um service principal."""
    sp_id: str
    app_id: str
    app_name: str
    permissions: list[str]
    third_party: bool = False  # app de outro tenant (multi-tenant / fornecedor)
    verified_publisher: bool = False
    has_owner: bool | None = None


@dataclass
class ConditionalAccessPolicy:
    name: str
    state: str  # enabled | disabled | enabledForReportingButNotEnforced
    requires_mfa: bool = False
    requires_phishing_resistant: bool = False
    blocks: bool = False
    targets_all_users: bool = False
    targets_admin_roles: bool = False
    targets_legacy_auth: bool = False


PHISHING_RESISTANT_METHODS = {"fido2", "windowsHelloForBusiness", "x509Certificate", "passKeyDeviceBound",
                              "passKeyDeviceBoundAuthenticator", "passKeyDeviceBoundWindowsHello"}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    target: str
    target_kind: str
    detail: str
    recommendation: str
    controls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class TenantSnapshot:
    tenant_name: str
    tenant_id: str
    collected_at: datetime
    accounts: list[Account] = field(default_factory=list)
    app_credentials: list[AppCredential] = field(default_factory=list)
    app_grants: list[AppPermissionGrant] = field(default_factory=list)
    ca_policies: list[ConditionalAccessPolicy] | None = None  # None = não consultado
    source: str = "graph"  # "graph" | "demo"
    warnings: list[str] = field(default_factory=list)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_dt(value: str | None) -> datetime | None:
    """Converte datas ISO-8601 do Graph (com 'Z' e frações variáveis)."""
    if not value:
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    # Graph às vezes retorna 7 casas decimais; fromisoformat aceita até 6.
    if "." in v:
        head, _, tail = v.partition(".")
        frac = ""
        rest = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                frac += ch
            else:
                rest = tail[i:]
                break
        v = f"{head}.{frac[:6].ljust(6, '0')}{rest}"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    # 0001-01-01 é usado pelo Graph como "nunca"
    if dt.year < 1971:
        return None
    return dt
