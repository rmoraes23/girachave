"""Regras de verificação (checks) com mapeamento para frameworks de controle.

Cada regra gera ``Finding``s com severidade, recomendação e os controles a
que se referem (ISO 27001:2022, CIS Controls v8, NIST CSF 2.0, PCI DSS 4.0,
LGPD, BACEN/CMN 4.893 e SOX ITGC) — o que transforma o achado técnico em
evidência de auditoria.

Famílias:
  GC-0xx  contas não nominais (serviço, genéricas, terceiros)
  GC-1xx  identidades não-humanas: segredos e permissões de aplicações (NHI)
  GC-2xx  postura de Acesso Condicional
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .models import (
    PHISHING_RESISTANT_METHODS,
    Account,
    AccountKind,
    AppCredential,
    AppPermissionGrant,
    ConditionalAccessPolicy,
    Finding,
    Severity,
    TenantSnapshot,
)

NON_PERSONAL = {AccountKind.SERVICE, AccountKind.GENERIC, AccountKind.EXTERNAL}

# Permissões de aplicação que equivalem a "chave do reino" no tenant.
# Abuso de apps OAuth com essas permissões foi o vetor de ataques
# recentes de alto perfil contra tenants Microsoft.
CRITICAL_APP_PERMISSIONS = {
    "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All", "Directory.ReadWrite.All", "User.ReadWrite.All",
    "Domain.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess",
    "UserAuthenticationMethod.ReadWrite.All", "User-PasswordProfile.ReadWrite.All",
}
SENSITIVE_DATA_PERMISSIONS = {
    "Mail.ReadWrite", "Mail.Read", "Mail.Send", "Files.ReadWrite.All", "Files.Read.All",
    "Sites.ReadWrite.All", "Sites.FullControl.All", "Sites.Read.All", "Chat.Read.All",
    "ChannelMessage.Read.All", "Calendars.ReadWrite", "full_access_as_app",
}


@dataclass(frozen=True)
class Policy:
    max_password_age_days: int = 90
    stale_days: int = 90
    never_used_grace_days: int = 30
    secret_expiry_warning_days: int = 30
    max_secret_lifetime_days: int = 365


CATALOG: dict[str, dict] = {
    "GC-001": {"title": "Senha não rotacionada dentro da política",
               "controls": ["ISO 27001 A.5.17", "CIS 5.2", "PCI DSS 8.3.9", "PCI DSS 8.6.3", "NIST CSF PR.AA-01",
                            "SOX ITGC – Acesso lógico"]},
    "GC-002": {"title": "Senha configurada para nunca expirar",
               "controls": ["ISO 27001 A.5.17", "CIS 5.2", "PCI DSS 8.3.9"]},
    "GC-003": {"title": "Conta sem MFA registrado",
               "controls": ["ISO 27001 A.8.5", "CIS 6.3", "PCI DSS 8.4.2", "NIST CSF PR.AA-03", "LGPD Art. 46",
                            "BACEN 4.893 Art. 3º"]},
    "GC-004": {"title": "Conta habilitada e inativa (dormente)",
               "controls": ["ISO 27001 A.5.18", "CIS 5.3", "PCI DSS 8.2.6", "NIST CSF PR.AA-05",
                            "SOX ITGC – Revisão de acesso"]},
    "GC-005": {"title": "Conta criada e nunca utilizada",
               "controls": ["ISO 27001 A.5.16", "CIS 5.1", "CIS 5.3"]},
    "GC-006": {"title": "Papel administrativo em conta não nominal",
               "controls": ["ISO 27001 A.8.2", "CIS 5.4", "PCI DSS 8.2.2", "PCI DSS 7.2.5", "NIST CSF PR.AA-05",
                            "SOX ITGC – Acesso privilegiado"]},
    "GC-007": {"title": "Conta não nominal sem responsável definido",
               "controls": ["ISO 27001 A.5.16", "CIS 5.5", "PCI DSS 8.6.1", "SOX ITGC – Accountability"]},
    "GC-008": {"title": "Administrador sem MFA resistente a phishing",
               "controls": ["ISO 27001 A.8.5", "CIS 6.5", "NIST CSF PR.AA-03", "BACEN 4.893 Art. 3º"]},
    "GC-101": {"title": "Segredo de aplicação expirado ainda cadastrado",
               "controls": ["ISO 27001 A.5.17", "CIS 5.1"]},
    "GC-102": {"title": "Segredo de aplicação prestes a expirar",
               "controls": ["ISO 27001 A.5.17", "ISO 27001 A.8.14"]},
    "GC-103": {"title": "Segredo de aplicação com validade longa demais",
               "controls": ["ISO 27001 A.5.17", "CIS 5.2", "PCI DSS 8.6.3"]},
    "GC-104": {"title": "Aplicação autenticando por segredo em vez de certificado",
               "controls": ["ISO 27001 A.8.5", "ISO 27001 A.8.24"]},
    "GC-105": {"title": "Identidade não-humana com permissão crítica no tenant",
               "controls": ["ISO 27001 A.8.2", "CIS 5.4", "PCI DSS 7.2.5", "NIST CSF PR.AA-05",
                            "SOX ITGC – Acesso privilegiado"]},
    "GC-106": {"title": "Aplicação de terceiro com acesso amplo a dados",
               "controls": ["ISO 27001 A.5.19", "ISO 27001 A.5.21", "LGPD Art. 39", "LGPD Art. 46",
                            "NIST CSF GV.SC-07"]},
    "GC-107": {"title": "Aplicação privilegiada sem dono definido",
               "controls": ["ISO 27001 A.5.9", "CIS 5.5", "PCI DSS 8.6.1"]},
    "GC-201": {"title": "Autenticação legada não bloqueada",
               "controls": ["ISO 27001 A.8.5", "CIS 4.8", "NIST CSF PR.AA-03"]},
    "GC-202": {"title": "Administradores sem exigência de MFA no Acesso Condicional",
               "controls": ["ISO 27001 A.8.5", "CIS 6.5", "PCI DSS 8.4.1", "BACEN 4.893 Art. 3º"]},
    "GC-203": {"title": "Política de Acesso Condicional apenas em modo relatório",
               "controls": ["ISO 27001 A.8.5", "NIST CSF PR.AA-03"]},
    "GC-204": {"title": "Nenhuma política exige MFA para todos os usuários",
               "controls": ["ISO 27001 A.8.5", "CIS 6.3", "PCI DSS 8.4.2", "LGPD Art. 46"]},
}


def _days(now: datetime, dt: datetime | None) -> int | None:
    return None if dt is None else (now - dt).days


def _f(check_id: str, sev: Severity, target: str, kind: str, detail: str, rec: str) -> Finding:
    meta = CATALOG[check_id]
    return Finding(check_id, meta["title"], sev, target, kind, detail, rec, list(meta["controls"]))


# ---------------------------------------------------------------- contas
def check_account(acc: Account, now: datetime, p: Policy) -> list[Finding]:
    out: list[Finding] = []

    # GC-008 vale para qualquer admin, inclusive pessoal: é o alvo nº 1 de phishing (AiTM)
    if acc.enabled and acc.roles and acc.mfa_methods is not None and acc.mfa_registered is not None:
        if not (set(acc.mfa_methods) & PHISHING_RESISTANT_METHODS):
            out.append(_f(
                "GC-008", Severity.HIGH, acc.upn, acc.kind.value,
                f"Papéis: {', '.join(acc.roles)}. Métodos: {', '.join(acc.mfa_methods) or 'nenhum'}.",
                "Exija força de autenticação 'MFA resistente a phishing' (FIDO2/passkey ou "
                "Windows Hello) para papéis administrativos — SMS e push são vulneráveis a AiTM.",
            ))

    if acc.kind not in NON_PERSONAL:
        return out
    k = acc.kind.value

    if acc.roles and acc.enabled:
        out.append(_f(
            "GC-006", Severity.CRITICAL, acc.upn, k,
            f"Papéis atribuídos: {', '.join(acc.roles)}.",
            "Remova o papel ou mova-o para uma conta administrativa nominal com PIM "
            "(ativação just-in-time) e MFA resistente a phishing.",
        ))

    age = _days(now, acc.last_password_change)
    if acc.enabled and age is not None and age > p.max_password_age_days:
        sev = Severity.HIGH if age > 365 else Severity.MEDIUM
        if acc.roles:
            sev = Severity.CRITICAL
        out.append(_f(
            "GC-001", sev, acc.upn, k,
            f"Última troca de senha há {age} dias (política: {p.max_password_age_days}).",
            "Rotacione com o Girachave — a nova senha vai direto para o Azure Key Vault, "
            "sem passar por e-mail, chat ou planilha.",
        ))

    if acc.enabled and acc.password_never_expires and acc.kind != AccountKind.SERVICE:
        out.append(_f(
            "GC-002", Severity.MEDIUM, acc.upn, k,
            "passwordPolicies contém DisablePasswordExpiration.",
            "Remova a exceção ou compense com rotação automática programada.",
        ))

    if acc.enabled and acc.mfa_registered is False:
        if acc.kind == AccountKind.SERVICE:
            sev = Severity.MEDIUM
            rec = ("Contas de serviço não fazem MFA: bloqueie login interativo via Acesso "
                   "Condicional (restrição por IP/local) ou migre para identidade gerenciada.")
        else:
            sev = Severity.HIGH
            rec = "Exija MFA via Acesso Condicional; para contas compartilhadas, use chave FIDO2 custodiada."
        out.append(_f("GC-003", sev, acc.upn, k, "Nenhum método MFA registrado.", rec))

    idle = _days(now, acc.last_sign_in)
    created_age = _days(now, acc.created)
    if acc.enabled and idle is not None and idle > p.stale_days:
        sev = Severity.HIGH if acc.kind == AccountKind.EXTERNAL else Severity.MEDIUM
        out.append(_f(
            "GC-004", sev, acc.upn, k,
            f"Último login há {idle} dias (limite: {p.stale_days}).",
            "Desabilite a conta e abra revisão de acesso (Access Review) com o responsável."
            + (" Acesso de fornecedor órfão é vetor clássico de invasão." if acc.kind == AccountKind.EXTERNAL else ""),
        ))
    elif (acc.enabled and acc.last_sign_in is None and created_age is not None
          and created_age > p.never_used_grace_days and acc.kind != AccountKind.SERVICE):
        out.append(_f(
            "GC-005", Severity.LOW, acc.upn, k,
            f"Criada há {created_age} dias, sem registro de login.",
            "Confirme a necessidade da conta; se não houver, exclua.",
        ))

    if acc.enabled and acc.has_owner is False:
        out.append(_f(
            "GC-007", Severity.LOW, acc.upn, k,
            "Nenhum gerente/responsável atribuído no diretório.",
            "Defina um responsável (campo manager) — ele recebe os avisos de rotação e as revisões.",
        ))
    return out


# ------------------------------------------------- identidades não-humanas
def check_app_credential(c: AppCredential, now: datetime, p: Policy) -> list[Finding]:
    out: list[Finding] = []
    target = f"{c.app_name} ({c.app_id})"
    label = f"{'Segredo' if c.cred_type == 'secret' else 'Certificado'} {c.hint or c.key_id[:8]}"
    if c.end is not None:
        remaining = (c.end - now).days
        if remaining < 0:
            out.append(_f(
                "GC-101", Severity.LOW, target, "aplicacao",
                f"{label} expirou há {-remaining} dias e continua cadastrado.",
                "Remova credenciais expiradas para reduzir ruído e superfície de ataque.",
            ))
        elif remaining <= p.secret_expiry_warning_days:
            out.append(_f(
                "GC-102", Severity.MEDIUM, target, "aplicacao",
                f"{label} expira em {remaining} dias.",
                "Programe a renovação agora para evitar parada da integração.",
            ))
        if c.start is not None and c.cred_type == "secret" and remaining >= 0:
            lifetime = (c.end - c.start).days
            if lifetime > p.max_secret_lifetime_days:
                out.append(_f(
                    "GC-103", Severity.MEDIUM, target, "aplicacao",
                    f"{label} com validade total de {lifetime} dias.",
                    f"Limite segredos a {p.max_secret_lifetime_days} dias (política de app management do Entra).",
                ))
    return out


def check_app_grant(g: AppPermissionGrant) -> list[Finding]:
    out: list[Finding] = []
    target = f"{g.app_name} ({g.app_id})"
    perms = set(g.permissions)
    critical = sorted(perms & CRITICAL_APP_PERMISSIONS)
    data = sorted(perms & SENSITIVE_DATA_PERMISSIONS)

    if critical:
        out.append(_f(
            "GC-105", Severity.CRITICAL, target, "aplicacao",
            f"Permissões de aplicação: {', '.join(critical)}"
            + (" — app de terceiro" if g.third_party else "") + ".",
            "Reduza ao mínimo necessário; restrinja com Application Access Policy/RBAC for Applications "
            "e monitore o service principal com alertas de sign-in.",
        ))
    if g.third_party and data:
        sev = Severity.HIGH if not g.verified_publisher else Severity.MEDIUM
        out.append(_f(
            "GC-106", sev, target, "aplicacao",
            f"App externo{' (editor não verificado)' if not g.verified_publisher else ''} "
            f"lê dados sensíveis: {', '.join(data)}.",
            "Revise o contrato/DPA com o fornecedor (LGPD), limite o escopo (ex.: só caixas "
            "específicas) e habilite revisão periódica de consentimentos.",
        ))
    if (critical or data) and g.has_owner is False:
        out.append(_f(
            "GC-107", Severity.MEDIUM, target, "aplicacao",
            "Service principal com permissões sensíveis e nenhum dono atribuído.",
            "Atribua ao menos dois donos responsáveis pela revisão das permissões.",
        ))
    return out


# --------------------------------------------------- Acesso Condicional
def check_conditional_access(policies: list[ConditionalAccessPolicy]) -> list[Finding]:
    out: list[Finding] = []
    enabled = [p for p in policies if p.state == "enabled"]

    if not any(p.blocks and p.targets_legacy_auth for p in enabled):
        out.append(_f(
            "GC-201", Severity.HIGH, "Acesso Condicional", "politica",
            "Nenhuma política ativa bloqueia protocolos legados (IMAP/POP/SMTP AUTH/EAS básico).",
            "Crie política 'Bloquear autenticação legada' para todos os usuários — protocolos "
            "legados ignoram MFA e são a porta de entrada de password spray.",
        ))
    if not any(p.targets_admin_roles and (p.requires_mfa or p.requires_phishing_resistant)
               for p in enabled) and not any(p.targets_all_users and p.requires_mfa for p in enabled):
        out.append(_f(
            "GC-202", Severity.CRITICAL, "Acesso Condicional", "politica",
            "Nenhuma política ativa exige MFA para papéis administrativos.",
            "Crie política exigindo força de autenticação resistente a phishing para todos os papéis de administrador.",
        ))
    if not any(p.targets_all_users and p.requires_mfa for p in enabled):
        out.append(_f(
            "GC-204", Severity.HIGH, "Acesso Condicional", "politica",
            "Não há política ativa exigindo MFA para todos os usuários.",
            "Exija MFA para todos (com exclusão apenas das contas de emergência 'break-glass').",
        ))
    for p in policies:
        if p.state == "enabledForReportingButNotEnforced":
            out.append(_f(
                "GC-203", Severity.LOW, p.name, "politica",
                "Política está em 'somente relatório' — não protege nada.",
                "Avalie os logs do modo relatório e ative a política.",
            ))
    return out


def run_checks(snapshot: TenantSnapshot, policy: Policy | None = None, now: datetime | None = None) -> list[Finding]:
    p = policy or Policy()
    now = now or snapshot.collected_at
    findings: list[Finding] = []
    for acc in snapshot.accounts:
        findings.extend(check_account(acc, now, p))

    by_app: dict[str, list[AppCredential]] = {}
    for c in snapshot.app_credentials:
        findings.extend(check_app_credential(c, now, p))
        by_app.setdefault(c.app_object_id, []).append(c)

    for creds in by_app.values():
        active = [c for c in creds if c.end is None or c.end > now]
        if active and all(c.cred_type == "secret" for c in active):
            c = active[0]
            findings.append(_f(
                "GC-104", Severity.LOW, f"{c.app_name} ({c.app_id})", "aplicacao",
                f"{len(active)} segredo(s) ativo(s) e nenhum certificado.",
                "Prefira certificado ou federated credential (workload identity) a client secret.",
            ))

    for g in snapshot.app_grants:
        findings.extend(check_app_grant(g))

    if snapshot.ca_policies is not None:
        findings.extend(check_conditional_access(snapshot.ca_policies))

    findings.sort(key=lambda f: (f.severity.rank, f.check_id, f.target))
    return findings
