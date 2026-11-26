"""Alertas no Microsoft Teams (Workflows / Incoming Webhook).

A URL do webhook é um segredo: vem de GIRACHAVE_TEAMS_WEBHOOK, e só são
aceitos hosts da Microsoft (evita exfiltração de achados para terceiros).
"""
from __future__ import annotations

import json
import os
import urllib.parse

from .graph import _http
from .models import Finding, Severity
from .scoring import Score

ALLOWED_SUFFIXES = (".webhook.office.com", ".logic.azure.com", ".powerplatform.com", ".environment.api.powerplatform.com")


def _host_ok(url: str) -> str:
    p = urllib.parse.urlparse(url)
    host = p.hostname or ""
    if p.scheme != "https" or not host.endswith(ALLOWED_SUFFIXES):
        raise ValueError("Webhook deve ser HTTPS em domínio Microsoft (webhook.office.com / logic.azure.com / Power Platform)")
    return host


def build_card(tenant: str, score: Score, findings: list[Finding], drift: dict | None = None,
               report_hint: str = "") -> dict:
    top = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)][:8]
    facts = [{"title": s.label, "value": str(score.by_severity[s.value])} for s in Severity]
    body = [
        {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": f"Girachave · {tenant}"},
        {"type": "TextBlock", "text": f"Score de exposição: **{score.value}/100 ({score.grade} – {score.label})**",
         "wrap": True},
        {"type": "FactSet", "facts": facts},
    ]
    if drift:
        body.append({"type": "TextBlock", "wrap": True,
                     "text": f"Desde a última varredura: **{len(drift['new'])} novos**, "
                             f"**{len(drift['resolved'])} resolvidos**."})
    if top:
        body.append({"type": "TextBlock", "weight": "Bolder", "text": "Prioridades", "spacing": "Medium"})
        for f in top:
            body.append({"type": "TextBlock", "wrap": True,
                         "text": f"🔴 **{f.check_id}** {f.title} — `{f.target}`"
                         if f.severity == Severity.CRITICAL else
                         f"🟠 **{f.check_id}** {f.title} — `{f.target}`"})
    if report_hint:
        body.append({"type": "TextBlock", "isSubtle": True, "wrap": True, "text": report_hint})
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard", "version": "1.4", "body": body},
        }],
    }


def send_teams(card: dict, url: str | None = None) -> None:
    url = url or os.environ.get("GIRACHAVE_TEAMS_WEBHOOK")
    if not url:
        raise SystemExit("Defina GIRACHAVE_TEAMS_WEBHOOK com a URL do webhook do Teams.")
    host = _host_ok(url)
    _http("POST", url, {"Content-Type": "application/json"}, json.dumps(card).encode(),
          retries=2, extra_hosts={host})
