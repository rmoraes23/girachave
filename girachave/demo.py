"""Tenant fictício para demonstrações comerciais — nenhum dado real.

Os cenários reproduzem o que mais aparece em diagnósticos de empresas
médias brasileiras 100% Microsoft.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from .classifier import classify_all
from .models import (
    Account,
    AppCredential,
    AppPermissionGrant,
    ConditionalAccessPolicy,
    TenantSnapshot,
    utcnow,
)

DOMAIN = "contosobr.onmicrosoft.com"


def _ago(now: datetime, days: int | None) -> datetime | None:
    return None if days is None else now - timedelta(days=days)


# upn, nome, pwd_age, last_login, criada, mfa, roles, never_expires, owner, enabled, guest, depto
_ACCOUNTS = [
    ("svc-backup-financeiro", "Serviço Backup Financeiro", 412, 1, 1500, False, [], True, False, True, False, "TI"),
    ("svc-integracao-erp", "Integração ERP", 38, 0, 900, False, [], True, True, True, False, "TI"),
    ("svc-relatorios-bi", "Relatórios Power BI", 260, 2, 700, False, [], True, False, True, False, "Dados"),
    ("sa-sync-ad", "Sincronização AD", 730, 0, 2100, False, ["Global Administrator"], True, False, True, False, "TI"),
    ("rpa-notas-fiscais", "Robô Notas Fiscais", 95, 0, 400, False, [], True, True, True, False, "Fiscal"),
    ("admin-generico-ti", "Admin TI (compartilhado)", 180, 3, 1800, False, ["Exchange Administrator", "User Administrator"], False, False, True, False, "TI"),
    ("suporte.n1", "Suporte N1", 120, 1, 1000, True, ["Helpdesk Administrator"], False, True, True, False, "TI"),
    ("recepcao.matriz", "Recepção Matriz", 540, 0, 1600, False, [], True, False, True, False, "Facilities"),
    ("financeiro.pagamentos", "Financeiro Pagamentos", 200, 0, 1300, True, [], False, True, True, False, "Financeiro"),
    ("treinamento.temp", "Usuário Treinamento", 300, None, 300, False, [], False, False, True, False, "RH"),
    ("sala.reuniao3", "Sala de Reunião 3", 30, 200, 800, None, [], True, True, True, False, "Facilities"),
    ("fornecedor.vpn.acme", "ACME Consultoria (VPN)", 400, 210, 600, False, [], True, False, True, False, "Fornecedor"),
    ("terceiro.suporte.datacenter", "Datacenter Terceirizado", 60, 5, 500, False, [], False, True, True, False, "Terceiro"),
    ("consultor.sap_parceiro.com#EXT#", "Consultor SAP (convidado)", None, 130, 400, False, [], False, False, True, True, ""),
    ("auditor_bigfour.com#EXT#", "Auditoria Externa (convidado)", None, 20, 90, True, [], False, True, True, True, ""),
    # contas pessoais — não geram achados (fora do escopo do produto)
    ("ana.souza", "Ana Souza", 20, 0, 1200, True, [], False, True, True, False, "Financeiro"),
    ("bruno.lima", "Bruno Lima", 400, 1, 900, True, ["Global Administrator"], False, True, True, False, "TI"),
    ("carla.mendes", "Carla Mendes", 15, 0, 600, True, [], False, True, True, False, "Fiscal"),
    ("diego.alves", "Diego Alves", 70, 2, 500, True, [], False, True, True, False, "Comercial"),
    ("elisa.rocha", "Elisa Rocha", 40, 0, 300, True, [], False, True, True, False, "RH"),
    ("fabio.nunes", "Fábio Nunes", 10, 0, 200, True, [], False, True, True, False, "Dados"),
    ("gabriela.castro", "Gabriela Castro", 85, 4, 1500, True, [], False, True, True, False, "Jurídico"),
    ("henrique.dias", "Henrique Dias", 30, 1, 800, True, [], False, True, True, False, "Comercial"),
    ("svc-antigo-crm", "CRM Legado (desativado)", 1500, 900, 2500, False, [], True, False, False, False, "TI"),
]

# app, segredo/cert, criado há, expira em (dias a partir de hoje), hint
_APPS = [
    ("Integração ERP → Banco", "secret", 700, 1095 - 700, "Xk9"),
    ("Integração ERP → Banco", "secret", 1200, -100, "aQ2"),
    ("Portal do Cliente", "secret", 340, 25, "p0R"),
    ("Power Automate – Notas Fiscais", "secret", 100, 630, "Zz1"),
    ("Power Automate – Notas Fiscais", "certificate", 100, 265, "CN=nf-automacao"),
    ("App de RH (legado)", "secret", 800, -40, "Lg7"),
    ("Conector SIEM", "certificate", 30, 335, "CN=siem-collector"),
    ("Webhook Teams Alertas", "secret", 60, 12, "wT4"),
]


# app, permissões de aplicação, de terceiro?, editor verificado?, tem dono?
_GRANTS = [
    ("Integração ERP → Banco", ["User.Read.All"], False, False, True),
    ("Ferramenta de Backup M365 (SaaS)", ["Mail.ReadWrite", "Files.ReadWrite.All", "Sites.FullControl.All"], True, True, True),
    ("Assinatura de E-mail Corporativo", ["Mail.ReadWrite", "User.ReadWrite.All"], True, False, False),
    ("Script de Provisionamento (TI)", ["Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory"], False, False, False),
    ("Conector SIEM", ["AuditLog.Read.All", "SecurityEvents.Read.All"], False, False, True),
]

# nome, estado, mfa, anti-phishing, bloqueia, todos, admins, legado
_CA = [
    ("Exigir MFA – Administradores", "enabled", True, False, False, False, True, False),
    ("Bloquear autenticação legada", "enabledForReportingButNotEnforced", False, False, True, True, False, True),
    ("Exigir MFA – Acesso externo à rede", "enabled", True, False, False, False, False, False),
]

# métodos MFA por conta (o restante recebe autenticador por push)
_MFA_METHODS = {
    "suporte.n1": ["microsoftAuthenticatorPush", "mobilePhone"],
    "bruno.lima": ["mobilePhone"],
    "auditor_bigfour.com#EXT#": ["microsoftAuthenticatorPush"],
}


def build_demo_snapshot(now: datetime | None = None) -> TenantSnapshot:
    now = now or utcnow()
    accounts = []
    for i, (local, name, pwd, login, created, mfa, roles, nexp, owner, enabled, guest, dept) in enumerate(_ACCOUNTS):
        upn = f"{local}@{DOMAIN}"
        accounts.append(Account(
            id=f"00000000-0000-4000-8000-{i:012d}",
            upn=upn,
            display_name=name,
            enabled=enabled,
            user_type="Guest" if guest else "Member",
            created=_ago(now, created),
            last_password_change=_ago(now, pwd),
            last_sign_in=_ago(now, login),
            password_never_expires=nexp,
            mfa_registered=mfa,
            mfa_methods=_MFA_METHODS.get(local, ["microsoftAuthenticatorPush"] if mfa else []),
            roles=list(roles),
            has_owner=owner,
            department=dept,
        ))
    classify_all(accounts)

    creds = []
    app_ids: dict[str, int] = {}
    for name, ctype, created, expires_in, hint in _APPS:
        idx = app_ids.setdefault(name, len(app_ids))
        creds.append(AppCredential(
            app_object_id=f"app-{idx}",
            app_id=f"11111111-2222-4333-8444-{idx:012d}",
            app_name=name,
            key_id=f"key-{len(creds):04d}",
            cred_type=ctype,
            start=_ago(now, created),
            end=now + timedelta(days=expires_in),
            hint=hint,
        ))

    grants = [
        AppPermissionGrant(
            sp_id=f"sp-{i}", app_id=f"33333333-4444-4555-8666-{i:012d}", app_name=name,
            permissions=perms, third_party=third, verified_publisher=verified, has_owner=owner,
        )
        for i, (name, perms, third, verified, owner) in enumerate(_GRANTS)
    ]
    ca = [ConditionalAccessPolicy(*row) for row in _CA]

    return TenantSnapshot(
        tenant_name="Contoso Brasil (demonstração)",
        tenant_id="demo",
        collected_at=now,
        accounts=accounts,
        app_credentials=creds,
        app_grants=grants,
        ca_policies=ca,
        source="demo",
    )
