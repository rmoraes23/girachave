"""Cliente mínimo do Microsoft Graph (somente biblioteca padrão).

Decisões de segurança:
- Credenciais vêm de variáveis de ambiente, nunca de argumentos de linha de
  comando (que ficam no histórico do shell e na lista de processos).
- Toda URL seguida (inclusive @odata.nextLink) é validada contra uma
  lista de hosts permitidos — evita SSRF/vazamento do token.
- TLS sempre verificado; timeouts e retentativas com backoff em 429/5xx.
- O token nunca é registrado em log.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
LOGIN_HOST = "login.microsoftonline.com"
ALLOWED_HOSTS = {"graph.microsoft.com", LOGIN_HOST}
USER_AGENT = "girachave/1.0"


class GraphError(RuntimeError):
    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.url = url


@dataclass
class Credentials:
    tenant_id: str
    client_id: str
    client_secret: str

    @classmethod
    def from_env(cls) -> "Credentials":
        missing = [n for n in ("GIRACHAVE_TENANT_ID", "GIRACHAVE_CLIENT_ID", "GIRACHAVE_CLIENT_SECRET")
                   if not os.environ.get(n)]
        if missing:
            raise SystemExit(
                "Variáveis de ambiente ausentes: " + ", ".join(missing)
                + "\nConfigure o App Registration (veja README) ou use --demo."
            )
        return cls(os.environ["GIRACHAVE_TENANT_ID"], os.environ["GIRACHAVE_CLIENT_ID"],
                   os.environ["GIRACHAVE_CLIENT_SECRET"])

    def __repr__(self) -> str:  # nunca expor o segredo em tracebacks/logs
        return f"Credentials(tenant_id={self.tenant_id!r}, client_id={self.client_id!r}, client_secret='***')"


def _check_url(url: str, extra_hosts: set[str] | None = None) -> None:
    parsed = urllib.parse.urlparse(url)
    allowed = ALLOWED_HOSTS | (extra_hosts or set())
    if parsed.scheme != "https" or parsed.hostname not in allowed:
        raise GraphError(0, f"URL bloqueada pela allowlist: {parsed.scheme}://{parsed.hostname}", url)


def _http(method: str, url: str, headers: dict, body: bytes | None = None,
          timeout: int = 30, retries: int = 4, extra_hosts: set[str] | None = None) -> tuple[int, dict]:
    _check_url(url, extra_hosts)
    headers = {"User-Agent": USER_AGENT, **headers}
    attempt = 0
    while True:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                wait = e.headers.get("Retry-After")
                delay = int(wait) if wait and wait.isdigit() else 2 ** attempt
                time.sleep(min(delay, 60))
                attempt += 1
                continue
            try:
                msg = json.loads(raw).get("error", {})
                msg = msg.get("message") if isinstance(msg, dict) else (msg or raw[:200])
            except (ValueError, AttributeError):
                msg = raw[:200].decode(errors="replace")
            raise GraphError(e.code, str(msg), url) from None
        except urllib.error.URLError as e:
            if attempt < retries:
                time.sleep(2 ** attempt)
                attempt += 1
                continue
            raise GraphError(0, f"Falha de rede: {e.reason}", url) from None


def acquire_token(creds: Credentials, scope: str = "https://graph.microsoft.com/.default") -> str:
    url = f"https://{LOGIN_HOST}/{urllib.parse.quote(creds.tenant_id)}/oauth2/v2.0/token"
    body = urllib.parse.urlencode({
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scope": scope,
        "grant_type": "client_credentials",
    }).encode()
    _, data = _http("POST", url, {"Content-Type": "application/x-www-form-urlencoded"}, body)
    token = data.get("access_token")
    if not token:
        raise GraphError(0, "Token não retornado pelo Entra ID")
    return token


class GraphClient:
    def __init__(self, token: str):
        self._token = token

    def __repr__(self) -> str:
        return "GraphClient(token='***')"

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json",
                "ConsistencyLevel": "eventual"}

    def get(self, path: str, root: str = GRAPH_ROOT) -> dict:
        url = path if path.startswith("https://") else f"{root}{path}"
        return _http("GET", url, self._headers())[1]

    def get_all(self, path: str, root: str = GRAPH_ROOT, max_pages: int = 500) -> list[dict]:
        url = path if path.startswith("https://") else f"{root}{path}"
        items: list[dict] = []
        for _ in range(max_pages):
            data = _http("GET", url, self._headers())[1]
            items.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            if not url:
                break
        return items

    def patch(self, path: str, payload: dict) -> None:
        _http("PATCH", f"{GRAPH_ROOT}{path}", {**self._headers(), "Content-Type": "application/json"},
              json.dumps(payload).encode(), retries=0)
