"""Relatório de avaliação externa (por empresa), painel de prospecção e
rascunho de e-mail de abordagem. Nada é enviado automaticamente."""
from __future__ import annotations

import re
from html import escape

from . import __version__
from .models import Severity
from .prospect import ProspectResult
from .report import CSS, SEV_COLOR

# O que cada achado significa para quem não é técnico (dono, diretor, financeiro)
PLAIN = {
    "PX-001": "Golpistas podem mandar e-mails usando o endereço da empresa — boleto falso, pedido de pagamento, "
              "phishing para clientes — e os provedores não têm instrução para bloquear.",
    "PX-002": "A proteção contra e-mails falsos existe, mas está só observando: mensagens fraudulentas ainda chegam.",
    "PX-003": "Não há lista de servidores autorizados a enviar e-mail pela empresa — facilita falsificação e faz "
              "e-mails legítimos caírem no spam.",
    "PX-004": "A configuração de remetentes autorizados está aberta ou quebrada e não cumpre seu papel.",
    "PX-005": "Os e-mails não levam assinatura digital — mais chance de spam e de adulteração sem detecção.",
    "PX-006": "Visitantes veem alerta de 'site não seguro' e os dados digitados podem ser interceptados.",
    "PX-007": "Quando o certificado vencer, o site passa a exibir erro de segurança para todos os visitantes.",
    "PX-008": "Quem acessa por http:// navega sem criptografia.",
    "PX-009": "O navegador não é instruído a usar sempre conexão segura.",
    "PX-010": "Faltam proteções básicas do site contra ataques como clickjacking e injeção de conteúdo.",
}

INSIDE_CHECKS = [
    "Contas de serviço e genéricas com senha antiga ou papel de administrador",
    "Acessos de fornecedores e ex-colaboradores ainda ativos",
    "Aplicativos e integrações com acesso amplo a e-mails e arquivos",
    "Administradores sem MFA resistente a phishing",
    "Brechas no Acesso Condicional (ex.: autenticação legada liberada)",
    "Evidências para ISO 27001, LGPD, PCI DSS e SOX",
]


def _level(r: ProspectResult) -> tuple[str, str]:
    sev = {f.severity for f in r.findings}
    if Severity.CRITICAL in sev or Severity.HIGH in sev:
        return "Exposição relevante", SEV_COLOR["critica"]
    if Severity.MEDIUM in sev:
        return "Pontos de atenção", SEV_COLOR["alta"]
    if r.findings:
        return "Boa base, ajustes finos", SEV_COLOR["media"]
    return "Nenhuma exposição externa visível", "#5FAE86"


def _status_row(label: str, ok: bool | None, value: str) -> str:
    icon = {True: ("✓", "#5FAE86"), False: ("✗", "#E0565B"), None: ("–", "#57626C")}[ok]
    return (f"<tr><td style='width:28px;color:{icon[1]};font-weight:700'>{icon[0]}</td><td>{escape(label)}</td>"
            f"<td class='mono target'>{escape(value)}</td></tr>")


def render_company(r: ProspectResult, contact: str = "", sender: str = "") -> str:
    level, color = _level(r)
    date = r.checked_at.strftime("%d/%m/%Y")
    pol = "—"
    if r.dmarc:
        m = re.search(r"\bp=([a-z]+)", r.dmarc.lower())
        pol = f"p={m.group(1)}" if m else r.dmarc[:40]
    rows = "".join([
        _status_row("Provedor de e-mail", None, r.mail_provider),
        _status_row("Identidade Microsoft (Entra ID)", None,
                    {"Managed": "gerenciada na nuvem", "Federated": f"federada ({r.federation_brand or 'ADFS/IdP'})"}
                    .get(r.identity, "não identificada")),
        _status_row("SPF (remetentes autorizados)", bool(r.spf) if r.mx else None, r.spf[0][:70] if r.spf else "ausente"),
        _status_row("DMARC (bloqueio de e-mail falso)",
                    (bool(r.dmarc) and "p=none" not in r.dmarc.lower()) if r.mx else None, pol if r.dmarc else "ausente"),
        _status_row("DKIM (assinatura digital)", bool(r.dkim_selectors) if r.mx else None,
                    ", ".join(r.dkim_selectors) or "não encontrado"),
        _status_row("Site com HTTPS válido", r.https_ok,
                    f"certificado vence em {r.cert_days_left} dias" if r.cert_days_left is not None else "—"),
        _status_row("Proteções do navegador (HSTS e cabeçalhos)",
                    None if r.https_ok is not True else (r.hsts and not r.missing_headers),
                    "completas" if r.https_ok and r.hsts and not r.missing_headers
                    else ("ausentes: " + ", ".join((["HSTS"] if r.hsts is False else []) + r.missing_headers))
                    if r.https_ok else "—"),
    ])

    cards = []
    for f in r.findings:
        cards.append(
            f"<div class='card' style='margin-bottom:12px'><div style='display:flex;gap:10px;align-items:center'>"
            f"<span class='pill' style='background:{SEV_COLOR[f.severity.value]}'>{escape(f.severity.label)}</span>"
            f"<strong>{escape(f.title)}</strong></div>"
            f"<p style='margin-top:10px'>{escape(PLAIN.get(f.check_id, ''))}</p>"
            f"<div class='d' style='color:var(--mut);margin-top:6px;font-size:13px'>Evidência técnica: {escape(f.detail)}</div>"
            f"<div class='r' style='margin-top:8px;font-size:13px'>→ {escape(f.recommendation)}</div>"
            f"<div style='margin-top:8px'>{''.join(f'<span class=chip>{escape(c)}</span>' for c in f.controls)}</div></div>")
    findings_html = "".join(cards) or "<p class='sub'>Nenhuma falha visível de fora. Ótimo sinal — o próximo passo é olhar por dentro.</p>"
    m365_hint = ("<p class='sub' style='margin-top:8px'>Identificamos que a empresa utiliza <strong>Microsoft 365</strong>. "
                 "Com autorização, o diagnóstico interno avalia o ambiente em menos de um dia, sem instalar nada.</p>"
                 if r.uses_m365 else "")
    sender_html = f"<p class='sub' style='margin-top:10px'>{escape(sender)}</p>" if sender else ""

    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="robots" content="noindex">
<title>Avaliação externa de segurança · {escape(r.company)}</title><style>{CSS}</style></head><body>
<header><div class="wrap"><div class="logo"><i></i>Girachave</div><span class="badge">Avaliação externa · {date}</span></div></header>
<section style="border-bottom:none;padding-bottom:6px"><div class="wrap">
<div class="eyebrow">Avaliação externa de segurança — somente informações públicas</div>
<h1>{escape(r.company)}</h1>
<p class="sub">Domínio analisado: <span class="mono">{escape(r.domain)}</span></p>
</div></section>
<section><div class="wrap"><div class="grid g-hero">
<div class="card score"><div style="font-size:54px;font-weight:700;color:{color}">{len(r.findings)}</div>
<div class="sub">ponto(s) de atenção</div><div class="lab" style="color:{color}">{escape(level)}</div></div>
<div class="card"><table><tbody>{rows}</tbody></table></div></div></div></section>
<section><div class="wrap"><div class="eyebrow">O que encontramos</div><h2>Riscos visíveis de fora</h2>
<p class="sub" style="margin-bottom:16px">Em linguagem simples, com a evidência técnica para o time de TI.</p>
{findings_html}</div></section>
<section><div class="wrap"><div class="eyebrow">O que não é visível de fora</div>
<h2>Os maiores riscos costumam estar dentro do ambiente</h2>
<p class="sub" style="margin:6px 0 14px">Esta avaliação viu só a superfície pública. Com autorização, o diagnóstico Girachave verifica:</p>
<div class="grid g3">{''.join(f"<div class='card' style='font-size:13.5px'>{escape(x)}</div>" for x in INSIDE_CHECKS)}</div>
{m365_hint}</div></section>
<section style="border-bottom:none"><div class="wrap"><div class="cta">
<h2>Quer o diagnóstico completo, sem custo?</h2>
<p class="sub" style="margin-top:6px">Leitura somente via Microsoft Graph, sem agente, com relatório e plano de ação. {escape(contact)}</p>
{sender_html}</div></div></section>
<footer><div class="wrap">Metodologia: consultas a DNS público (MX, SPF, DMARC, DKIM), ao serviço público de descoberta
de login da Microsoft e uma visita à página inicial do site. Nenhum sistema foi acessado, testado ou varrido.
Os itens do site refletem a resposta recebida na data da avaliação (CDNs e firewalls podem responder de forma diferente).
Girachave v{escape(__version__)}. Se não deseja receber comunicações, responda “remover” e excluiremos seus dados (LGPD).</div></footer>
</body></html>"""


def email_draft(r: ProspectResult, sender: str = "", contact: str = "") -> str:
    top = [f for f in r.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)] or r.findings
    if top:
        subject = f"{r.company}: {len(r.findings)} ponto(s) de segurança visíveis no domínio {r.domain}"
        bullets = "\n".join(f"  • {f.title}: {PLAIN.get(f.check_id, '')}" for f in top[:3])
        hook = f"Fiz uma avaliação externa, usando só informações públicas, do domínio {r.domain} e encontrei:\n\n{bullets}"
    else:
        subject = f"{r.company}: avaliação de segurança do domínio {r.domain}"
        hook = (f"Fiz uma avaliação externa do domínio {r.domain} e a configuração pública está em bom nível — "
                "parabéns ao time. O que não aparece de fora são as contas e integrações internas.")
    m365 = (" Como vocês usam Microsoft 365, consigo verificar também contas de serviço, acessos de terceiros e "
            "aplicativos com acesso amplo — que é onde costumam estar os maiores riscos." if r.uses_m365 else "")
    return f"""Assunto: {subject}

Olá, tudo bem?

{hook}

Preparei um relatório curto com a explicação de cada ponto e como corrigir (anexo).{m365}

Se fizer sentido, ofereço um diagnóstico completo, sem custo e sem instalar nada. Posso explicar em 15 minutos?

{sender or '[seu nome · cargo · telefone]'}
{contact}

—
Avaliação feita apenas com informações públicas (DNS e página inicial do site); nenhum sistema foi acessado.
Se não quiser receber novos contatos, responda "remover" e excluo seus dados (LGPD).
"""


def render_index(results: list[ProspectResult], query: str = "") -> str:
    rows = []
    for r in sorted(results, key=lambda x: -x.opportunity):
        sev = {s: sum(1 for f in r.findings if f.severity == s) for s in Severity}
        pills = "".join(f"<span class='pill' style='background:{SEV_COLOR[s.value]};margin-right:4px'>{n}</span>"
                        for s, n in sev.items() if n)
        rows.append(
            f"<tr><td><div class='t'>{escape(r.company)}</div><div class='target mono'>{escape(r.domain)}</div></td>"
            f"<td>{escape(r.mail_provider)}</td><td>{pills or '<span class=sub>—</span>'}</td>"
            f"<td class='mono'><strong>{r.opportunity}</strong></td>"
            f"<td><a style='color:var(--amber)' href='{escape(r.domain)}/relatorio.html'>relatório</a> · "
            f"<a style='color:var(--amber)' href='{escape(r.domain)}/email.txt'>e-mail</a></td></tr>")
    m365 = sum(1 for r in results if r.uses_m365)
    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Painel de prospecção · Girachave</title><style>{CSS}</style></head><body>
<header><div class="wrap"><div class="logo"><i></i>Girachave</div><span class="badge">Uso interno · prospecção</span></div></header>
<section><div class="wrap"><div class="eyebrow">Painel de prospecção</div>
<h1>{len(results)} empresas avaliadas</h1>
<p class="sub">{escape(query) + ' · ' if query else ''}{m365} usam Microsoft 365 · ordenado por prioridade comercial
(riscos visíveis + aderência ao Girachave).</p></div></section>
<section style="border-bottom:none"><div class="wrap"><table><thead><tr><th>Empresa</th><th>E-mail</th>
<th>Achados</th><th>Prioridade</th><th>Arquivos</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></section>
</body></html>"""
