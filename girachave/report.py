"""Relatório HTML autocontido (sem JavaScript, sem recursos externos).

Pensado para ser entregue ao cliente: executivo no topo, técnico embaixo,
com plano de ação 30/60/90 e mapeamento para frameworks de auditoria.
Todo conteúdo dinâmico passa por ``html.escape``.
"""
from __future__ import annotations

import math
from collections import Counter
from html import escape

from . import __version__
from .checks import CATALOG
from .models import AccountKind, Finding, Severity, TenantSnapshot
from .scoring import Score

FRAMEWORKS = [
    ("ISO 27001", "ISO/IEC 27001:2022 – Anexo A"),
    ("CIS", "CIS Controls v8"),
    ("NIST CSF", "NIST Cybersecurity Framework 2.0"),
    ("PCI DSS", "PCI DSS v4.0"),
    ("LGPD", "LGPD – Lei 13.709/2018"),
    ("BACEN", "Resolução CMN 4.893/2021"),
    ("SOX", "SOX – ITGC"),
]

SEV_COLOR = {"critica": "#E0565B", "alta": "#F2A93B", "media": "#D9C36A", "baixa": "#7C8C9C"}
GRADE_COLOR = {"A": "#5FAE86", "B": "#9CC46A", "C": "#F2A93B", "D": "#E07B3B", "E": "#E0565B"}

FAMILIES = [
    ("GC-0", "Contas não nominais", "Serviço, genéricas/compartilhadas e de terceiros"),
    ("GC-1", "Identidades não-humanas (NHI)", "Segredos e permissões de aplicações e service principals"),
    ("GC-2", "Acesso Condicional", "Políticas que protegem (ou deveriam proteger) a autenticação"),
]

CSS = """
:root{--bg:#0C1116;--panel:#131A21;--panel2:#0F151B;--line:#232E38;--tx:#EDF1F4;--mut:#8592A0;--faint:#57626C;--amber:#F2A93B}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font:14px/1.55 'Segoe UI',Inter,system-ui,sans-serif;-webkit-font-smoothing:antialiased}
.mono{font-family:'Cascadia Mono',Consolas,'IBM Plex Mono',monospace}
.wrap{max-width:1100px;margin:0 auto;padding:0 28px}
header{border-bottom:1px solid var(--line);padding:22px 0}
header .wrap{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.logo{font-weight:700;font-size:18px;display:flex;align-items:center;gap:9px}
.logo i{width:9px;height:9px;border-radius:50%;background:var(--amber);box-shadow:0 0 0 4px rgba(242,169,59,.14);display:inline-block}
.badge{font-size:11px;letter-spacing:.08em;text-transform:uppercase;padding:4px 10px;border-radius:20px;border:1px solid var(--line);color:var(--mut)}
.badge.demo{color:var(--amber);border-color:#7A5A26;background:rgba(242,169,59,.08)}
h1{font-size:30px;letter-spacing:-.02em;line-height:1.15;margin:34px 0 6px}
h2{font-size:20px;letter-spacing:-.01em;margin:0 0 4px}
.sub{color:var(--mut)}
.eyebrow{font-size:11.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--amber);margin-bottom:8px}
section{padding:36px 0;border-bottom:1px solid var(--line)}
.grid{display:grid;gap:14px}
.g-hero{grid-template-columns:260px 1fr;align-items:stretch}
.g4{grid-template-columns:repeat(4,1fr)}
.g3{grid-template-columns:repeat(3,1fr)}
@media(max-width:820px){.g-hero,.g4,.g3{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px}
.kpi .n{font-size:30px;font-weight:700;letter-spacing:-.02em}
.kpi .l{color:var(--mut);font-size:12.5px}
.score{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}
.score .lab{margin-top:8px;font-weight:600}
.pill{display:inline-block;font-size:11px;font-weight:600;padding:2px 9px;border-radius:20px;color:#0C1116;white-space:nowrap}
.chip{display:inline-block;font-size:10.5px;padding:1px 7px;border-radius:4px;border:1px solid var(--line);color:var(--mut);margin:2px 3px 0 0;white-space:nowrap}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--faint);font-weight:500;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;padding:10px 10px;border-bottom:1px solid var(--line)}
td{padding:12px 10px;border-bottom:1px solid rgba(35,46,56,.6);vertical-align:top}
td .t{font-weight:600}
td .d{color:var(--mut);margin-top:3px}
td .r{margin-top:6px;color:#C9D2DA}
td .r::before{content:'→ ';color:var(--amber)}
.target{font-size:12px;color:#C9D2DA;word-break:break-all}
.bar{height:8px;border-radius:4px;background:var(--panel2);overflow:hidden;margin-top:6px}
.bar span{display:block;height:100%;background:var(--amber)}
.fw{display:flex;justify-content:space-between;gap:10px;font-size:13px}
.phase h3{font-size:15px;margin-bottom:2px}
.phase ul{list-style:none;margin-top:10px}
.phase li{padding:7px 0;border-top:1px solid var(--line);font-size:13px;color:#C9D2DA}
.phase li:first-child{border-top:none}
.warn{border-left:3px solid var(--amber);padding:10px 14px;background:rgba(242,169,59,.06);color:#E6D3B0;margin-top:10px;font-size:13px}
.drift .n{font-size:22px;font-weight:700}
.up{color:#E0565B}.down{color:#5FAE86}
footer{padding:30px 0 50px;color:var(--faint);font-size:12.5px}
.cta{background:linear-gradient(135deg,rgba(242,169,59,.12),rgba(242,169,59,.02));border:1px solid #7A5A26;border-radius:12px;padding:24px}
.cta a{color:var(--amber)}
@media print{body{background:#fff;color:#111}.card,.cta{background:#fff;border-color:#ccc}.sub,.kpi .l,td .d{color:#444}td .r,.target,.phase li{color:#222}header,section{border-color:#ccc}}
"""


def _pill(sev: Severity) -> str:
    return f'<span class="pill" style="background:{SEV_COLOR[sev.value]}">{escape(sev.label)}</span>'


def _ring(score: Score) -> str:
    r = 70
    c = 2 * math.pi * r
    filled = c * score.value / 100
    color = GRADE_COLOR[score.grade]
    return (f'<svg width="170" height="170" viewBox="0 0 170 170" role="img" aria-label="Score {score.value} de 100">'
            f'<circle cx="85" cy="85" r="{r}" fill="none" stroke="#232E38" stroke-width="12"/>'
            f'<circle cx="85" cy="85" r="{r}" fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round" '
            f'stroke-dasharray="{filled:.1f} {c:.1f}" transform="rotate(-90 85 85)"/>'
            f'<text x="85" y="88" text-anchor="middle" fill="#EDF1F4" font-size="40" font-weight="700">{score.value}</text>'
            f'<text x="85" y="114" text-anchor="middle" fill="#8592A0" font-size="12">de 100 · nota {score.grade}</text></svg>')


def _findings_table(findings: list[Finding]) -> str:
    if not findings:
        return '<p class="sub">Nenhum achado nesta categoria. 👏</p>'
    rows = []
    for f in findings:
        chips = "".join(f'<span class="chip">{escape(c)}</span>' for c in f.controls)
        rows.append(
            f"<tr><td>{_pill(f.severity)}<div class='mono chip' style='margin-top:6px'>{escape(f.check_id)}</div></td>"
            f"<td><div class='t'>{escape(f.title)}</div><div class='target mono'>{escape(f.target)}</div>"
            f"<div class='d'>{escape(f.detail)}</div><div class='r'>{escape(f.recommendation)}</div></td>"
            f"<td style='width:230px'>{chips}</td></tr>")
    return ("<table><thead><tr><th style='width:110px'>Risco</th><th>Achado e recomendação</th>"
            "<th>Controles</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def _action_plan(findings: list[Finding]) -> str:
    phases = [
        ("0–30 dias", "Conter", [Severity.CRITICAL]),
        ("30–60 dias", "Corrigir", [Severity.HIGH]),
        ("60–90 dias", "Sustentar", [Severity.MEDIUM, Severity.LOW]),
    ]
    cols = []
    for when, name, sevs in phases:
        items = Counter((f.check_id, f.title) for f in findings if f.severity in sevs)
        lis = "".join(f"<li><span class='mono' style='color:var(--amber)'>{escape(cid)}</span> {escape(t)}"
                      f"{f' <span class=sub>×{n}</span>' if n > 1 else ''}</li>"
                      for (cid, t), n in sorted(items.items()))
        if name == "Sustentar":
            lis += ("<li>Rotação automática agendada + revisão trimestral de acessos</li>"
                    "<li>Varredura contínua com alerta de desvios no Teams/SIEM</li>")
        cols.append(f"<div class='card phase'><div class='eyebrow'>{when}</div><h3>{name}</h3>"
                    f"<ul>{lis or '<li class=sub>Nada pendente</li>'}</ul></div>")
    return "<div class='grid g3'>" + "".join(cols) + "</div>"


def _frameworks(findings: list[Finding]) -> str:
    rows = []
    total = max(len(findings), 1)
    for prefix, name in FRAMEWORKS:
        hits = [f for f in findings if any(c.startswith(prefix) for c in f.controls)]
        ctrls = sorted({c for f in hits for c in f.controls if c.startswith(prefix)})
        pct = round(100 * len(hits) / total)
        rows.append(
            f"<div class='card'><div class='fw'><strong>{escape(name)}</strong>"
            f"<span class='mono'>{len(hits)} achado(s)</span></div>"
            f"<div class='bar'><span style='width:{pct}%'></span></div>"
            f"<div style='margin-top:8px'>{''.join(f'<span class=chip>{escape(c)}</span>' for c in ctrls)}</div></div>")
    return "<div class='grid' style='grid-template-columns:repeat(auto-fill,minmax(320px,1fr))'>" + "".join(rows) + "</div>"


def _inventory(snapshot: TenantSnapshot) -> str:
    rows = []
    now = snapshot.collected_at
    for a in sorted(snapshot.accounts, key=lambda a: (a.kind.value, a.upn)):
        if a.kind == AccountKind.PERSONAL:
            continue
        pwd = f"{(now - a.last_password_change).days} d" if a.last_password_change else "—"
        login = f"{(now - a.last_sign_in).days} d" if a.last_sign_in else "nunca/sem dado"
        mfa = {True: "✓", False: "✗", None: "?"}[a.mfa_registered]
        status = "" if a.enabled else " <span class='chip'>desabilitada</span>"
        rows.append(f"<tr><td class='target mono'>{escape(a.upn)}{status}</td><td>{escape(a.kind.label)}</td>"
                    f"<td class='mono'>{pwd}</td><td class='mono'>{login}</td><td class='mono'>{mfa}</td>"
                    f"<td>{escape(', '.join(a.roles)) or '—'}</td></tr>")
    return ("<table><thead><tr><th>Conta</th><th>Classificação</th><th>Idade da senha</th><th>Último login</th>"
            "<th>MFA</th><th>Papéis</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def render(snapshot: TenantSnapshot, findings: list[Finding], score: Score, drift: dict | None = None,
           contact: str = "") -> str:
    kinds = Counter(a.kind for a in snapshot.accounts)
    non_personal = sum(v for k, v in kinds.items() if k != AccountKind.PERSONAL)
    apps = len({c.app_object_id for c in snapshot.app_credentials} | {g.sp_id for g in snapshot.app_grants})
    demo = snapshot.source == "demo"
    date = snapshot.collected_at.strftime("%d/%m/%Y %H:%M UTC")
    top = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]

    sev_tiles = "".join(
        f"<div class='card kpi'><div class='n' style='color:{SEV_COLOR[s.value]}'>{score.by_severity[s.value]}</div>"
        f"<div class='l'>risco {escape(s.label.lower())}</div></div>" for s in Severity)

    drift_html = ""
    if drift:
        prev = drift.get("previous_score")
        delta = "" if prev is None else f"{score.value - prev:+d} pts"
        drift_html = (
            "<section><div class='wrap'><div class='eyebrow'>Monitoramento contínuo</div>"
            "<h2>O que mudou desde a última varredura</h2>"
            f"<p class='sub'>Comparado com a varredura de {escape(str(drift.get('previous_scan') or '?'))}.</p>"
            "<div class='grid g4' style='margin-top:16px'>"
            f"<div class='card drift'><div class='n up'>+{len(drift['new'])}</div><div class='sub'>novos achados</div></div>"
            f"<div class='card drift'><div class='n down'>−{len(drift['resolved'])}</div><div class='sub'>resolvidos</div></div>"
            f"<div class='card drift'><div class='n'>{drift['unchanged']}</div><div class='sub'>persistentes</div></div>"
            f"<div class='card drift'><div class='n'>{escape(delta) or '—'}</div><div class='sub'>variação do score</div></div>"
            "</div></div></section>")

    families = []
    for prefix, name, desc in FAMILIES:
        fam = [f for f in findings if f.check_id.startswith(prefix)]
        families.append(f"<section><div class='wrap'><div class='eyebrow'>{len(fam)} achado(s)</div>"
                        f"<h2>{escape(name)}</h2><p class='sub' style='margin-bottom:16px'>{escape(desc)}</p>"
                        f"{_findings_table(fam)}</div></section>")

    warnings = "".join(f"<div class='warn'>{escape(w)}</div>" for w in snapshot.warnings)
    checks_list = "".join(f"<span class='chip mono'>{escape(k)}</span>" for k in CATALOG)
    cta = (f"<div class='cta'><h2>Quer esse diagnóstico no seu tenant?</h2><p class='sub' style='margin-top:6px'>"
           f"Leitura somente via Microsoft Graph, sem agente, resultado no mesmo dia. {escape(contact)}</p></div>"
           if demo or contact else "")

    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="robots" content="noindex">
<title>Diagnóstico de identidades · {escape(snapshot.tenant_name)}</title>
<style>{CSS}</style></head><body>
<header><div class="wrap"><div class="logo"><i></i>Girachave</div>
<div><span class="badge{' demo' if demo else ''}">{'Dados fictícios · demonstração' if demo else 'Confidencial'}</span></div></div></header>

<section style="border-bottom:none;padding-bottom:10px"><div class="wrap">
<div class="eyebrow">Diagnóstico de identidades · Microsoft Entra ID</div>
<h1>{escape(snapshot.tenant_name)}</h1>
<p class="sub">Coletado em {date} · {len(snapshot.accounts)} contas, {apps} aplicações analisadas · {len(CATALOG)} verificações</p>
</div></section>

<section><div class="wrap"><div class="grid g-hero">
<div class="card score">{_ring(score)}<div class="lab" style="color:{GRADE_COLOR[score.grade]}">{escape(score.label)}</div></div>
<div class="grid" style="gap:14px">
<div class="grid g4">{sev_tiles}</div>
<div class="grid g4">
<div class="card kpi"><div class="n">{non_personal}</div><div class="l">contas não nominais</div></div>
<div class="card kpi"><div class="n">{kinds.get(AccountKind.SERVICE, 0)}</div><div class="l">contas de serviço</div></div>
<div class="card kpi"><div class="n">{kinds.get(AccountKind.EXTERNAL, 0)}</div><div class="l">terceiros / convidados</div></div>
<div class="card kpi"><div class="n">{len(snapshot.app_grants)}</div><div class="l">apps com permissão app-only</div></div>
</div></div></div>
{warnings}
</div></section>

<section><div class="wrap"><div class="eyebrow">Resumo executivo</div>
<h2>{len(top)} risco(s) crítico(s) ou alto(s) exigem ação imediata</h2>
<p class="sub" style="max-width:780px;margin-top:6px">Contas que não pertencem a uma pessoa — serviço, compartilhadas,
de fornecedores — e aplicações com permissões amplas ficam fora do fluxo passwordless e raramente são revisadas.
São exatamente essas identidades que atacantes procuram, e as primeiras que um auditor pede evidência.</p>
<div style="margin-top:20px">{_action_plan(findings)}</div></div></section>

{drift_html}
{''.join(families)}

<section><div class="wrap"><div class="eyebrow">Conformidade</div><h2>Mapeamento para frameworks</h2>
<p class="sub" style="margin-bottom:16px">Cada achado aponta o controle correspondente — pronto para anexar ao relatório de auditoria.</p>
{_frameworks(findings)}</div></section>

<section><div class="wrap"><div class="eyebrow">Inventário</div><h2>Contas não nominais identificadas</h2>
<p class="sub" style="margin-bottom:16px">Classificação automática do Girachave — o Entra ID não faz essa separação nativamente.</p>
{_inventory(snapshot)}</div></section>

<section style="border-bottom:none"><div class="wrap">{cta}</div></section>
<footer><div class="wrap">Girachave v{escape(__version__)} · Metodologia: coleta somente leitura via Microsoft Graph,
verificações {checks_list} · Este relatório é acompanhado de manifesto SHA-256 quando exportado como pacote de evidências.</div></footer>
</body></html>"""
