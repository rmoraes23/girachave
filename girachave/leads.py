"""Busca de empresas (leads) pela API oficial do Google Places.

Raspar o Google Maps viola os termos de uso do Google; a API oficial é o
caminho permitido. Crie uma chave em console.cloud.google.com (Places API
"New") e defina GOOGLE_PLACES_API_KEY. Há cota mensal gratuita; acima
disso a API é paga — confira o preço vigente no console.

Também é possível montar a lista à mão: um CSV com as colunas
``empresa;site`` (ou só ``site``) funciona da mesma forma.
"""
from __future__ import annotations

import csv
import io
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .prospect import ProspectError, normalize_domain

PLACES_URL = "https://places.googleapis.com/v1/places:searchText"
FIELD_MASK = ("places.displayName,places.websiteUri,places.formattedAddress,"
              "places.nationalPhoneNumber,places.primaryTypeDisplayName,nextPageToken")
# Sites que não são da empresa (perfis, marketplaces): não servem para avaliação
IGNORED_DOMAINS = ("instagram.com", "facebook.com", "wa.me", "whatsapp.com", "linktr.ee", "google.com",
                   "business.site", "linkedin.com", "ifood.com.br", "booking.com", "youtube.com")


@dataclass
class Lead:
    empresa: str
    site: str
    dominio: str
    endereco: str = ""
    telefone: str = ""
    segmento: str = ""


def search_places(query: str, max_results: int = 20, region: str = "br") -> list[Lead]:
    key = os.environ.get("GOOGLE_PLACES_API_KEY")
    if not key:
        raise SystemExit("Defina GOOGLE_PLACES_API_KEY (Google Cloud > Places API New) ou use --csv com sua lista.")
    leads: list[Lead] = []
    seen: set[str] = set()
    token = None
    while len(leads) < max_results:
        body = {"textQuery": query, "languageCode": "pt-BR", "regionCode": region, "pageSize": 20}
        if token:
            body["pageToken"] = token
        req = urllib.request.Request(PLACES_URL, data=json.dumps(body).encode(), method="POST", headers={
            "Content-Type": "application/json", "X-Goog-Api-Key": key, "X-Goog-FieldMask": FIELD_MASK})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            msg = e.read()[:300].decode(errors="replace")
            raise SystemExit(f"Google Places respondeu HTTP {e.code}: {msg}") from None
        for p in data.get("places", []):
            site = p.get("websiteUri") or ""
            try:
                dom = normalize_domain(site) if site else ""
            except ProspectError:
                dom = ""
            if not dom or dom.endswith(IGNORED_DOMAINS) or dom in seen:
                continue
            seen.add(dom)
            leads.append(Lead(
                empresa=(p.get("displayName") or {}).get("text", dom), site=site, dominio=dom,
                endereco=p.get("formattedAddress", ""), telefone=p.get("nationalPhoneNumber", ""),
                segmento=(p.get("primaryTypeDisplayName") or {}).get("text", ""),
            ))
            if len(leads) >= max_results:
                break
        token = data.get("nextPageToken")
        if not token:
            break
    return leads


def read_csv(path: str | Path) -> list[Lead]:
    text = Path(path).read_text(encoding="utf-8-sig")
    header = text.splitlines()[0] if text else ""
    delimiter = next((d for d in (";", ",", "\t") if d in header), ";")  # coluna única também funciona
    rows = list(csv.DictReader(io.StringIO(text), delimiter=delimiter))
    leads, seen = [], set()
    for row in rows:
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        site = row.get("site") or row.get("dominio") or row.get("website") or row.get("url") or ""
        try:
            dom = normalize_domain(site)
        except ProspectError:
            continue
        if dom in seen:
            continue
        seen.add(dom)
        leads.append(Lead(row.get("empresa") or row.get("nome") or dom, site, dom,
                          row.get("endereco", ""), row.get("telefone", ""), row.get("segmento", "")))
    return leads


def write_csv(leads: list[Lead], path: str | Path) -> None:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["empresa", "site", "dominio", "endereco", "telefone", "segmento"])
    for l in leads:
        w.writerow([("'" + v if v.startswith(("=", "+", "-", "@")) else v)
                    for v in (l.empresa, l.site, l.dominio, l.endereco, l.telefone, l.segmento)])
    Path(path).write_text("﻿" + buf.getvalue(), encoding="utf-8")
