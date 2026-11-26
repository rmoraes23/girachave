"""Coleta do inventário do tenant via Microsoft Graph (somente leitura).

Permissões de aplicação necessárias (todas *Read*):
  User.Read.All, Directory.Read.All, Application.Read.All,
  AuditLog.Read.All, UserAuthenticationMethod.Read.All, Policy.Read.All

Quando uma permissão ou licença (ex.: Entra ID P1 para signInActivity)
não está disponível, a coleta degrada graciosamente e registra um aviso
em vez de falhar.
"""
from __future__ import annotations

import urllib.parse

from .classifier import NON_PERSONAL_HINT, classify_all
from .graph import GraphClient, GraphError
from .models import (
    Account,
    AccountKind,
    AppCredential,
    AppPermissionGrant,
    ConditionalAccessPolicy,
    TenantSnapshot,
    parse_dt,
    utcnow,
)

USER_FIELDS = ("id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime,"
               "lastPasswordChangeDateTime,passwordPolicies,department")


def _users(client: GraphClient, warnings: list[str]) -> list[dict]:
    try:
        return client.get_all(f"/users?$select={USER_FIELDS},signInActivity&$top=999")
    except GraphError as e:
        if e.status in (400, 403):
            warnings.append("signInActivity indisponível (requer Entra ID P1 + AuditLog.Read.All): "
                            "checagens de inatividade foram ignoradas.")
            return client.get_all(f"/users?$select={USER_FIELDS}&$top=999")
        raise


def _mfa_map(client: GraphClient, warnings: list[str]) -> dict[str, tuple[bool, list[str]]]:
    try:
        rows = client.get_all("/reports/authenticationMethods/userRegistrationDetails?$top=999")
        return {r["id"]: (bool(r.get("isMfaRegistered")), list(r.get("methodsRegistered") or [])) for r in rows}
    except GraphError as e:
        warnings.append(f"Relatório de MFA indisponível ({e}); checagens GC-003/GC-008 ignoradas.")
        return {}


MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}


def _app_grants(client: GraphClient, tenant_id: str, warnings: list[str]) -> list[AppPermissionGrant]:
    """Permissões de aplicação (app-only) de cada service principal — o inventário de NHI."""
    grants: list[AppPermissionGrant] = []
    try:
        sps = client.get_all("/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,"
                             "verifiedPublisher,servicePrincipalType&$top=999")
    except GraphError as e:
        warnings.append(f"Service principals indisponíveis ({e}); checagens GC-105..107 ignoradas.")
        return grants

    role_cache: dict[str, dict[str, str]] = {}

    def role_names(resource_id: str) -> dict[str, str]:
        if resource_id not in role_cache:
            try:
                sp = client.get(f"/servicePrincipals/{urllib.parse.quote(resource_id)}?$select=appRoles")
                role_cache[resource_id] = {r["id"]: r.get("value") or r["id"] for r in sp.get("appRoles", [])}
            except GraphError:
                role_cache[resource_id] = {}
        return role_cache[resource_id]

    for sp in sps:
        owner_org = sp.get("appOwnerOrganizationId") or ""
        if owner_org in MICROSOFT_TENANTS or sp.get("servicePrincipalType") != "Application":
            continue
        try:
            assigns = client.get_all(f"/servicePrincipals/{urllib.parse.quote(sp['id'])}/appRoleAssignments")
        except GraphError:
            continue
        perms = sorted({role_names(a["resourceId"]).get(a["appRoleId"], a["appRoleId"]) for a in assigns})
        if not perms:
            continue
        try:
            owners = client.get_all(f"/servicePrincipals/{urllib.parse.quote(sp['id'])}/owners?$select=id")
            has_owner: bool | None = bool(owners)
        except GraphError:
            has_owner = None
        grants.append(AppPermissionGrant(
            sp_id=sp["id"], app_id=sp.get("appId", ""), app_name=sp.get("displayName") or sp.get("appId", ""),
            permissions=perms, third_party=bool(owner_org and owner_org != tenant_id),
            verified_publisher=bool((sp.get("verifiedPublisher") or {}).get("verifiedPublisherId")),
            has_owner=has_owner,
        ))
    return grants


PHISHING_RESISTANT_STRENGTH = "00000000-0000-0000-0000-000000000004"


def _ca_policies(client: GraphClient, warnings: list[str]) -> list[ConditionalAccessPolicy] | None:
    try:
        rows = client.get_all("/identity/conditionalAccess/policies")
    except GraphError as e:
        warnings.append(f"Acesso Condicional indisponível ({e}; requer Policy.Read.All): checagens GC-2xx ignoradas.")
        return None
    out = []
    for r in rows:
        cond = r.get("conditions") or {}
        users = cond.get("users") or {}
        grant = r.get("grantControls") or {}
        builtin = set(grant.get("builtInControls") or [])
        strength = (grant.get("authenticationStrength") or {}).get("id")
        out.append(ConditionalAccessPolicy(
            name=r.get("displayName") or r.get("id", "?"),
            state=r.get("state") or "disabled",
            requires_mfa="mfa" in builtin or bool(strength),
            requires_phishing_resistant=strength == PHISHING_RESISTANT_STRENGTH,
            blocks="block" in builtin,
            targets_all_users="All" in (users.get("includeUsers") or []),
            targets_admin_roles=bool(users.get("includeRoles")),
            targets_legacy_auth=bool({"exchangeActiveSync", "other"} & set(cond.get("clientAppTypes") or [])),
        ))
    return out


def _role_map(client: GraphClient, warnings: list[str]) -> dict[str, list[str]]:
    roles: dict[str, list[str]] = {}
    try:
        for role in client.get_all("/directoryRoles?$expand=members($select=id)"):
            for m in role.get("members", []):
                roles.setdefault(m["id"], []).append(role.get("displayName", "?"))
    except GraphError as e:
        warnings.append(f"Papéis de diretório indisponíveis ({e}); checagem GC-006 ignorada.")
    return roles


def _has_manager(client: GraphClient, user_id: str) -> bool | None:
    try:
        client.get(f"/users/{urllib.parse.quote(user_id)}/manager?$select=id")
        return True
    except GraphError as e:
        return False if e.status == 404 else None


def _apps(client: GraphClient, warnings: list[str]) -> list[AppCredential]:
    out: list[AppCredential] = []
    try:
        apps = client.get_all("/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999")
    except GraphError as e:
        warnings.append(f"Aplicações indisponíveis ({e}); checagens GC-1xx ignoradas.")
        return out
    for a in apps:
        for c in a.get("passwordCredentials") or []:
            out.append(AppCredential(a["id"], a["appId"], a.get("displayName") or a["appId"], c.get("keyId", ""),
                                     "secret", parse_dt(c.get("startDateTime")), parse_dt(c.get("endDateTime")),
                                     c.get("hint") or ""))
        for c in a.get("keyCredentials") or []:
            out.append(AppCredential(a["id"], a["appId"], a.get("displayName") or a["appId"], c.get("keyId", ""),
                                     "certificate", parse_dt(c.get("startDateTime")), parse_dt(c.get("endDateTime")),
                                     c.get("displayName") or ""))
    return out


def collect(client: GraphClient, extra_patterns: dict[str, list[str]] | None = None) -> TenantSnapshot:
    warnings: list[str] = []
    org = (client.get("/organization?$select=id,displayName").get("value") or [{}])[0]
    mfa = _mfa_map(client, warnings)
    roles = _role_map(client, warnings)

    accounts: list[Account] = []
    for u in _users(client, warnings):
        sia = u.get("signInActivity") or {}
        last = parse_dt(sia.get("lastSuccessfulSignInDateTime")) or parse_dt(sia.get("lastSignInDateTime"))
        accounts.append(Account(
            id=u["id"],
            upn=u.get("userPrincipalName") or u["id"],
            display_name=u.get("displayName") or "",
            enabled=bool(u.get("accountEnabled", True)),
            user_type=u.get("userType") or "Member",
            created=parse_dt(u.get("createdDateTime")),
            last_password_change=parse_dt(u.get("lastPasswordChangeDateTime")),
            last_sign_in=last,
            password_never_expires="DisablePasswordExpiration" in (u.get("passwordPolicies") or ""),
            mfa_registered=mfa[u["id"]][0] if u["id"] in mfa else None,
            mfa_methods=mfa[u["id"]][1] if u["id"] in mfa else [],
            roles=roles.get(u["id"], []),
            department=u.get("department") or "",
        ))

    classify_all(accounts, extra_patterns)
    # Consulta de responsável só para contas não nominais (economiza chamadas)
    for acc in accounts:
        if acc.kind in NON_PERSONAL_HINT:
            acc.has_owner = _has_manager(client, acc.id)

    return TenantSnapshot(
        tenant_name=org.get("displayName") or "tenant",
        tenant_id=org.get("id") or "",
        collected_at=utcnow(),
        accounts=accounts,
        app_credentials=_apps(client, warnings),
        app_grants=_app_grants(client, org.get("id") or "", warnings),
        ca_policies=_ca_policies(client, warnings),
        source="graph",
        warnings=warnings,
    )


__all__ = ["collect", "AccountKind"]
