"""Avaliação externa PASSIVA de um domínio, para prospecção comercial.

Usa somente informações públicas, as mesmas que qualquer servidor de e-mail
ou navegador consulta ao interagir com a empresa:

- DNS público (MX, SPF, DMARC, DKIM) via DNS-over-HTTPS;
- endpoint público de descoberta de login da Microsoft (se o domínio usa
  Microsoft 365 / Entra ID e se é gerenciado ou federado);
- UMA visita à página inicial do site (HTTPS, certificado, cabeçalhos).

Não há varredura de portas, força bruta, enumeração de usuários nem qualquer
tentativa de acesso. Ainda assim, use com responsabilidade: o diagnóstico
completo do Girachave só é feito com autorização da empresa.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import __version__
from .models import Finding, Severity

DOH_URL = "https://cloudflare-dns.com/dns-query"
USER_AGENT = f"Mozilla/5.0 (compatible; girachave-prospect/{__version__}; avaliacao-passiva)"
HOSTNAME_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
DKIM_KEY_RE = re.compile(r"(?:^|;)\s*p=[A-Za-z0-9+/]{40,}")
DKIM_SELECTORS = ["selector1", "selector2", "google", "default", "k1", "s1", "mail", "dkim"]
SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}

CATALOG = {
    "PX-001": ("Domínio sem política DMARC", ["CIS 9.5", "ISO 27001 A.5.14", "NIST CSF PR.DS-02"]),
    "PX-002": ("DMARC apenas em monitoramento (não bloqueia)", ["CIS 9.5", "ISO 27001 A.5.14"]),
    "PX-003": ("Domínio sem registro SPF", ["CIS 9.5", "ISO 27001 A.5.14"]),
    "PX-004": ("SPF permissivo ou inválido", ["CIS 9.5", "ISO 27001 A.5.14"]),
    "PX-005": ("Assinatura DKIM não encontrada", ["CIS 9.5", "ISO 27001 A.5.14"]),
    "PX-006": ("Site sem HTTPS válido", ["ISO 27001 A.8.24", "CIS 3.10", "PCI DSS 4.2.1", "LGPD Art. 46"]),
    "PX-007": ("Certificado do site perto de expirar", ["ISO 27001 A.8.24", "CIS 3.10"]),
    "PX-008": ("HTTP não redireciona para HTTPS", ["ISO 27001 A.8.24", "CIS 3.10", "OWASP ASVS V9"]),
    "PX-009": ("HSTS não configurado", ["ISO 27001 A.8.24", "OWASP ASVS V14.4"]),
    "PX-010": ("Cabeçalhos de segurança ausentes no site", ["ISO 27001 A.8.28", "OWASP ASVS V14.4"]),
}


class ProspectError(ValueError):
    pass


@dataclass
class ProspectResult:
    domain: str
    company: str = ""
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    mail_provider: str = "desconhecido"
    uses_m365: bool = False
    identity: str = ""  # Managed | Federated | Unknown
    federation_brand: str = ""
    mx: list[str] = field(default_factory=list)
    spf: list[str] = field(default_factory=list)
    dmarc: str = ""
    dkim_selectors: list[str] = field(default_factory=list)
    https_ok: bool | None = None
    cert_days_left: int | None = None
    http_redirects: bool | None = None
    missing_headers: list[str] = field(default_factory=list)
    hsts: bool | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def opportunity(self) -> int:
        """Prioridade comercial (0–100): risco visível + aderência ao Girachave."""
        pts = sum({"critica": 30, "alta": 20, "media": 10, "baixa": 4}[f.severity.value] for f in self.findings)
        if self.uses_m365:
            pts += 30
        if self.identity == "Federated":
            pts += 10
        return min(100, pts)


# ------------------------------------------------------------------ utilidades
def normalize_domain(value: str) -> str:
    v = (value or "").strip().lower()
    if "://" in v:
        v = urllib.parse.urlparse(v).hostname or ""
    v = v.split("/")[0].split(":")[0].strip(".")
    if v.startswith("www."):
        v = v[4:]
    try:
        v = v.encode("idna").decode()
    except UnicodeError:
        raise ProspectError(f"domínio inválido: {value!r}") from None
    if not HOSTNAME_RE.match(v):
        raise ProspectError(f"domínio inválido: {value!r}")
    return v


def _public_host(host: str) -> bool:
    """Bloqueia IPs privados/loopback (evita usar a ferramenta contra a rede interna)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


def _txt_join(data: str) -> str:
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(parts) if parts else data


def doh_query(name: str, rtype: str) -> list[str]:
    url = f"{DOH_URL}?{urllib.parse.urlencode({'name': name, 'type': rtype})}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
    code = {"TXT": 16, "MX": 15, "CNAME": 5}[rtype]
    return [a.get("data", "") for a in data.get("Answer") or [] if a.get("type") == code]


def user_realm(domain: str) -> dict:
    url = ("https://login.microsoftonline.com/getuserrealm.srf?"
           + urllib.parse.urlencode({"login": f"contato@{domain}", "json": "1"}))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


class _RecordingRedirect(urllib.request.HTTPRedirectHandler):
    """Guarda os cabeçalhos de cada salto (o HSTS costuma vir no 301 inicial)."""

    def __init__(self):
        self.hops: list[dict] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.hops.append({k.lower(): v for k, v in headers.items()})
        if not newurl.lower().startswith("https://"):
            return None  # não seguimos para http nem para outro esquema
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_probe(domain: str) -> dict:
    """Uma visita à home (https e http). Retorna cabeçalhos, redirecionamento e certificado."""
    out: dict = {"https_ok": None, "headers": {}, "http_redirects": None, "cert_days_left": None, "error": ""}
    host = domain
    for candidate in (domain, f"www.{domain}"):
        if _public_host(candidate):
            host = candidate
            break
    else:
        out["error"] = "site não resolve para IP público"
        return out

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                not_after = tls.getpeercert().get("notAfter")
                if not_after:
                    exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
                    out["cert_days_left"] = (exp - datetime.now(timezone.utc)).days
        rec = _RecordingRedirect()
        opener = urllib.request.build_opener(rec, urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(f"https://{host}/", headers={"User-Agent": USER_AGENT})
        try:
            with opener.open(req, timeout=12) as resp:
                out["headers"] = {k.lower(): v for k, v in resp.headers.items()}
        finally:
            out["chain_hsts"] = any("strict-transport-security" in h for h in rec.hops)
        out["https_ok"] = True
    except ssl.SSLCertVerificationError as e:
        msg = (getattr(e, "verify_message", "") or str(e)).lower()
        if any(k in msg for k in ("expired", "hostname mismatch", "self-signed", "self signed", "not valid for")):
            out["https_ok"] = False  # certificado comprovadamente inválido
        else:
            # Ex.: "unable to get local issuer certificate" — pode ser só a máquina
            # local sem a CA raiz. Não afirmamos falha que não podemos provar.
            out["https_ok"] = None
        out["error"] = f"TLS: {getattr(e, 'verify_message', '') or e}"
    except ssl.SSLError as e:
        out["https_ok"] = False
        out["error"] = f"TLS: {getattr(e, 'reason', e)}"
    except urllib.error.HTTPError as e:  # site respondeu com erro, mas o HTTPS funciona
        out["https_ok"] = True
        out["headers"] = {k.lower(): v for k, v in e.headers.items()}
    except (OSError, urllib.error.URLError) as e:
        out["https_ok"] = False
        out["error"] = f"HTTPS indisponível: {getattr(e, 'reason', e)}"

    try:
        opener = urllib.request.build_opener(_NoRedirect)
        opener.open(urllib.request.Request(f"http://{host}/", headers={"User-Agent": USER_AGENT}), timeout=10)
        out["http_redirects"] = False
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location", "") if e.code in (301, 302, 303, 307, 308) else ""
        out["http_redirects"] = loc.lower().startswith("https://")
    except (OSError, urllib.error.URLError):
        out["http_redirects"] = None  # porta 80 fechada: ok
    return out


# ------------------------------------------------------------------ avaliação
def _f(cid: str, sev: Severity, target: str, detail: str, rec: str) -> Finding:
    title, controls = CATALOG[cid]
    return Finding(cid, title, sev, target, "dominio", detail, rec, list(controls))


def evaluate(r: ProspectResult) -> list[Finding]:
    d = r.domain
    out: list[Finding] = []
    sends_mail = bool(r.mx)

    if sends_mail:
        if not r.dmarc:
            out.append(_f("PX-001", Severity.HIGH, d,
                          "Não existe registro _dmarc. Qualquer pessoa pode enviar e-mails se passando pelo domínio.",
                          "Publique DMARC começando em p=none com relatórios (rua) e evolua para p=reject."))
        else:
            policy = (re.search(r"\bp=([a-z]+)", r.dmarc.lower()) or [None, ""])[1]
            pct = re.search(r"\bpct=(\d+)", r.dmarc.lower())
            if policy == "none":
                out.append(_f("PX-002", Severity.MEDIUM, d, f"Política atual: {r.dmarc}",
                              "Após analisar os relatórios, mude para p=quarantine e depois p=reject."))
            elif pct and int(pct.group(1)) < 100:
                out.append(_f("PX-002", Severity.LOW, d, f"Política aplicada só a {pct.group(1)}% das mensagens.",
                              "Aumente pct para 100."))

        if not r.spf:
            out.append(_f("PX-003", Severity.HIGH, d, "Nenhum registro v=spf1 publicado.",
                          "Publique SPF listando apenas os servidores autorizados e terminando em -all ou ~all."))
        elif len(r.spf) > 1:
            out.append(_f("PX-004", Severity.MEDIUM, d, f"{len(r.spf)} registros SPF (a RFC exige apenas um).",
                          "Una os registros em um só — com dois, o SPF é tratado como inválido."))
        elif re.search(r"[+?]all\b", r.spf[0]) or not re.search(r"[-~]all\b|redirect=", r.spf[0]):
            out.append(_f("PX-004", Severity.HIGH, d, f"SPF: {r.spf[0]}",
                          "Termine o SPF em -all (ou ~all durante a transição): '+all'/'?all' autoriza qualquer servidor."))

        if not r.dkim_selectors:
            out.append(_f("PX-005", Severity.LOW, d,
                          "Nenhuma chave DKIM nos seletores mais comuns (selector1/2, google, default...).",
                          "Habilite a assinatura DKIM no provedor de e-mail (no Microsoft 365: Defender > DKIM)."))

    if r.https_ok is False:
        out.append(_f("PX-006", Severity.HIGH, d, "O site não oferece HTTPS com certificado válido.",
                      "Instale certificado válido (ex.: Let's Encrypt) e force HTTPS."))
    elif r.https_ok:
        if r.cert_days_left is not None and r.cert_days_left < 21:
            out.append(_f("PX-007", Severity.MEDIUM, d, f"Certificado expira em {r.cert_days_left} dias.",
                          "Renove o certificado e automatize a renovação."))
        if r.http_redirects is False:
            out.append(_f("PX-008", Severity.MEDIUM, d, "A versão http:// do site é servida sem redirecionar.",
                          "Redirecione todo o tráfego HTTP para HTTPS (301)."))
        if r.hsts is False:
            out.append(_f("PX-009", Severity.LOW, d, "Cabeçalho Strict-Transport-Security ausente.",
                          "Adicione HSTS (max-age de pelo menos 6 meses)."))
        if len(r.missing_headers) >= 2:
            out.append(_f("PX-010", Severity.LOW, d, "Ausentes: " + ", ".join(r.missing_headers) + ".",
                          "Configure os cabeçalhos no servidor/CDN — protegem contra clickjacking e injeção de conteúdo."))

    out.sort(key=lambda f: (f.severity.rank, f.check_id))
    return out


def assess(domain: str, company: str = "", *, dns: Callable[[str, str], list[str]] = doh_query,
           realm: Callable[[str], dict] = user_realm, probe: Callable[[str], dict] = http_probe) -> ProspectResult:
    d = normalize_domain(domain)
    r = ProspectResult(domain=d, company=company or d)

    def safe(fn, *a, default=None, label=""):
        try:
            return fn(*a)
        except Exception as e:  # uma checagem falhar não derruba as outras
            r.errors.append(f"{label}: {str(e)[:120]}")
            return default

    mx_raw = (m.split()[-1].rstrip(".").lower() for m in safe(dns, d, "MX", default=[], label="MX") if m.strip())
    r.mx = sorted(m for m in mx_raw if m)  # "0 ." = MX nulo (RFC 7505): domínio não recebe e-mail
    mx_all = " ".join(r.mx)
    if "mail.protection.outlook.com" in mx_all:
        r.mail_provider = "Microsoft 365"
    elif "google.com" in mx_all or "googlemail.com" in mx_all:
        r.mail_provider = "Google Workspace"
    elif r.mx:
        r.mail_provider = "outro / gateway"
    else:
        r.mail_provider = "sem e-mail no domínio"

    txt = [_txt_join(t) for t in safe(dns, d, "TXT", default=[], label="TXT")]
    r.spf = [t for t in txt if t.lower().startswith("v=spf1")]
    dmarc = [_txt_join(t) for t in safe(dns, f"_dmarc.{d}", "TXT", default=[], label="DMARC")]
    r.dmarc = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), "")

    for sel in DKIM_SELECTORS:
        answers = safe(dns, f"{sel}._domainkey.{d}", "TXT", default=[], label=f"DKIM {sel}")
        # exige chave pública de verdade: "p=" vazio significa chave revogada/curinga
        if any(DKIM_KEY_RE.search(_txt_join(a)) for a in answers):
            r.dkim_selectors.append(sel)

    info = safe(realm, d, default={}, label="Microsoft") or {}
    ns = info.get("NameSpaceType") or ""
    # IsViral = tenant "não gerenciado" criado por autocadastro: não é cliente Microsoft 365
    if ns in ("Managed", "Federated") and not info.get("IsViral"):
        r.uses_m365 = True
        r.identity = ns
        r.federation_brand = info.get("FederationBrandName") or ""
        if r.mail_provider not in ("Microsoft 365",):
            r.mail_provider = r.mail_provider + " (tenant Microsoft ativo)"

    web = safe(probe, d, default={}, label="site") or {}
    r.https_ok = web.get("https_ok")
    r.cert_days_left = web.get("cert_days_left")
    r.http_redirects = web.get("http_redirects")
    if web.get("error"):
        r.errors.append(f"site: {web['error']}")
    headers = web.get("headers") or {}
    if r.https_ok:
        r.hsts = "strict-transport-security" in headers or bool(web.get("chain_hsts"))
        csp = headers.get("content-security-policy", "")
        r.missing_headers = [label for key, label in SECURITY_HEADERS.items()
                             if key not in headers and not (key == "x-frame-options" and "frame-ancestors" in csp)]

    r.findings = evaluate(r)
    return r
