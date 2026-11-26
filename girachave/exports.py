"""Exportações: CSV/JSON, eventos para SIEM, pacote de evidências e drift."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from datetime import datetime
from pathlib import Path

from . import __version__
from .models import Finding, TenantSnapshot, utcnow
from .scoring import Score

CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(value) -> str:
    """Neutraliza injeção de fórmulas (CSV injection) ao abrir no Excel."""
    s = "" if value is None else str(value)
    return "'" + s if s.startswith(CSV_INJECTION_PREFIXES) else s


def _iso(dt: datetime | None) -> str:
    return dt.isoformat(timespec="seconds") if dt else ""


def findings_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["id", "severidade", "titulo", "alvo", "tipo", "detalhe", "recomendacao", "controles"])
    for f in findings:
        w.writerow([_safe_cell(x) for x in (f.check_id, f.severity.label, f.title, f.target, f.target_kind,
                                             f.detail, f.recommendation, " | ".join(f.controls))])
    return "﻿" + buf.getvalue()  # BOM: acentos corretos no Excel pt-BR


def inventory_csv(snapshot: TenantSnapshot) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["upn", "nome", "classificacao", "habilitada", "tipo_usuario", "ultima_troca_senha",
                "ultimo_login", "mfa", "metodos_mfa", "papeis", "tem_responsavel"])
    for a in snapshot.accounts:
        w.writerow([_safe_cell(x) for x in (
            a.upn, a.display_name, a.kind.value, a.enabled, a.user_type, _iso(a.last_password_change),
            _iso(a.last_sign_in), a.mfa_registered, ",".join(a.mfa_methods), ",".join(a.roles), a.has_owner)])
    return "﻿" + buf.getvalue()


def findings_json(snapshot: TenantSnapshot, findings: list[Finding], score: Score) -> str:
    return json.dumps({
        "tool": "girachave", "version": __version__,
        "tenant": snapshot.tenant_name, "tenant_id": snapshot.tenant_id, "source": snapshot.source,
        "collected_at": _iso(snapshot.collected_at),
        "score": {"value": score.value, "grade": score.grade, "label": score.label,
                  "by_severity": score.by_severity},
        "warnings": snapshot.warnings,
        "findings": [f.to_dict() for f in findings],
    }, ensure_ascii=False, indent=2)


def fingerprint(f: Finding) -> str:
    """Identidade estável de um achado (para drift e deduplicação no SIEM)."""
    return hashlib.sha256(f"{f.check_id}|{f.target}".encode()).hexdigest()[:16]


SEVERITY_NUM = {"critica": 90, "alta": 70, "media": 50, "baixa": 25}


def siem_jsonl(snapshot: TenantSnapshot, findings: list[Finding]) -> str:
    """Um evento por linha, campos no estilo ECS — ingestão direta no Microsoft
    Sentinel (tabela custom via DCR), Splunk, Elastic ou Wazuh."""
    ts = _iso(snapshot.collected_at)
    lines = []
    for f in findings:
        lines.append(json.dumps({
            "@timestamp": ts,
            "event": {"kind": "alert", "category": ["iam"], "module": "girachave", "code": f.check_id,
                      "severity": SEVERITY_NUM[f.severity.value], "id": fingerprint(f)},
            "rule": {"id": f.check_id, "name": f.title, "reference": f.controls},
            "observer": {"vendor": "Girachave", "product": "girachave", "version": __version__},
            "cloud": {"provider": "azure", "account": {"id": snapshot.tenant_id, "name": snapshot.tenant_name}},
            "user": {"name": f.target} if f.target_kind not in ("aplicacao", "politica") else None,
            "girachave": {"target": f.target, "target_kind": f.target_kind, "severity": f.severity.value,
                          "detail": f.detail, "recommendation": f.recommendation},
        }, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


def drift(previous: dict, findings: list[Finding]) -> dict:
    """Compara com uma varredura anterior (findings.json): novos x resolvidos."""
    prev = {hashlib.sha256(f"{f['check_id']}|{f['target']}".encode()).hexdigest()[:16]: f
            for f in previous.get("findings", [])}
    curr = {fingerprint(f): f for f in findings}
    new = [curr[k].to_dict() for k in curr.keys() - prev.keys()]
    resolved = [prev[k] for k in prev.keys() - curr.keys()]
    return {
        "previous_scan": previous.get("collected_at"),
        "previous_score": (previous.get("score") or {}).get("value"),
        "new": sorted(new, key=lambda f: f["check_id"]),
        "resolved": sorted(resolved, key=lambda f: f["check_id"]),
        "unchanged": len(curr.keys() & prev.keys()),
    }


def build_evidence_pack(out_zip: Path, files: dict[str, bytes], snapshot: TenantSnapshot, score: Score) -> dict:
    """ZIP com manifesto SHA-256 de cada arquivo — o auditor confere a integridade."""
    manifest = {
        "tool": "girachave", "version": __version__, "generated_at": _iso(utcnow()),
        "tenant": snapshot.tenant_name, "tenant_id": snapshot.tenant_id,
        "collected_at": _iso(snapshot.collected_at),
        "score": {"value": score.value, "grade": score.grade},
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                  for name, data in sorted(files.items())},
    }
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode()
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(files.items()):
            z.writestr(name, data)
        z.writestr("MANIFEST.json", manifest_bytes)
        z.writestr("MANIFEST.sha256", hashlib.sha256(manifest_bytes).hexdigest() + "  MANIFEST.json\n")
    return manifest
