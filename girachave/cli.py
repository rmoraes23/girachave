"""Interface de linha de comando do Girachave."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .auditlog import AuditLog, verify
from .checks import CATALOG, Policy, run_checks
from .models import Severity, TenantSnapshot
from .scoring import compute

DEFAULT_LOG = "girachave-audit.jsonl"


# ------------------------------------------------------------ saída
def _color(code: str, text: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"\033[{code}m{text}\033[0m"


SEV_ANSI = {"critica": "1;31", "alta": "33", "media": "93", "baixa": "90"}


def _banner() -> None:
    print(_color("1;33", "●") + _color("1", " Girachave") + _color("90", f" v{__version__} · identidades do Entra ID sob controle"))


def _snapshot(args) -> tuple[TenantSnapshot, object | None]:
    if args.demo:
        from .demo import build_demo_snapshot
        return build_demo_snapshot(), None
    from .collector import collect
    from .graph import Credentials, GraphClient, acquire_token
    creds = Credentials.from_env()
    print(_color("90", f"Conectando ao tenant {creds.tenant_id} (somente leitura)..."))
    client = GraphClient(acquire_token(creds))
    return collect(client), client


# ------------------------------------------------------------ scan
def cmd_scan(args) -> int:
    from . import exports, report

    _banner()
    snap, _ = _snapshot(args)
    policy = Policy(max_password_age_days=args.max_password_age, stale_days=args.stale_days)
    findings = run_checks(snap, policy)
    score = compute(findings)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    previous_path = Path(args.compare) if args.compare else out / "findings.json"
    drift = None
    if previous_path.exists():
        try:
            drift = exports.drift(json.loads(previous_path.read_text(encoding="utf-8")), findings)
        except (ValueError, KeyError):
            print(_color("33", f"Aviso: não foi possível ler {previous_path} para comparação."))

    files = {
        "relatorio.html": report.render(snap, findings, score, drift, args.contact).encode("utf-8"),
        "findings.json": exports.findings_json(snap, findings, score).encode("utf-8"),
        "findings.csv": exports.findings_csv(findings).encode("utf-8"),
        "inventario.csv": exports.inventory_csv(snap).encode("utf-8"),
        "siem.jsonl": exports.siem_jsonl(snap, findings).encode("utf-8"),
    }
    if drift:
        files["drift.json"] = json.dumps(drift, ensure_ascii=False, indent=2).encode("utf-8")
    for name, data in files.items():
        (out / name).write_bytes(data)

    log = AuditLog(args.log)
    log.append("scan.completed", {"tenant": snap.tenant_name, "source": snap.source, "score": score.value,
                                  "findings": len(findings), "by_severity": score.by_severity})

    # resumo no terminal
    print()
    print(f"  Tenant: {_color('1', snap.tenant_name)}" + (_color("33", "  [DEMO]") if snap.source == "demo" else ""))
    print(f"  Score de exposição: {_color('1', f'{score.value}/100')} — nota {score.grade} ({score.label})")
    print("  " + "  ".join(_color(SEV_ANSI[s.value], f"{s.label}: {score.by_severity[s.value]}") for s in Severity))
    if drift:
        print(f"  Desde a última varredura: {_color('31', '+' + str(len(drift['new'])))} novos, "
              f"{_color('32', '-' + str(len(drift['resolved'])))} resolvidos")
    for w in snap.warnings:
        print(_color("33", f"  ! {w}"))
    print()
    for f in findings[: args.top]:
        sev = _color(SEV_ANSI[f.severity.value], f"{f.severity.label:<8}")
        print(f"  {sev} {f.check_id}  {f.title}")
        print(_color("90", f"           {f.target}"))
    if len(findings) > args.top:
        print(_color("90", f"  ... e mais {len(findings) - args.top} no relatório."))

    if args.evidence:
        log_path = Path(args.log)
        if log_path.exists():
            files["audit-log.jsonl"] = log_path.read_bytes()
        zip_path = out / f"evidencias-{snap.collected_at.strftime('%Y%m%d-%H%M%S')}.zip"
        exports.build_evidence_pack(zip_path, files, snap, score)
        log.append("evidence.exported", {"file": zip_path.name})
        print(f"\n  Pacote de evidências: {zip_path}")

    if args.teams:
        from .notify import build_card, send_teams
        send_teams(build_card(snap.tenant_name, score, findings, drift, f"Relatório: {out / 'relatorio.html'}"))
        log.append("alert.teams_sent", {"findings": len(findings)})
        print("  Alerta enviado ao Teams.")

    print(f"\n  Relatório: {_color('1', str(out / 'relatorio.html'))}\n")
    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        if any(f.severity.rank <= threshold for f in findings):
            return 2  # útil em pipelines / agendamentos
    return 0


# ------------------------------------------------------------ rotate
def cmd_rotate(args) -> int:
    from . import rotation

    _banner()
    snap, client = _snapshot(args)
    items = rotation.plan(snap, args.max_password_age, only=args.only)
    if not items:
        print("\n  Nenhuma conta elegível para rotação. ✓\n")
        return 0

    mode = "SIMULAÇÃO (demo)" if args.demo else ("EXECUÇÃO" if args.apply else "DRY-RUN — nada será alterado")
    print(f"\n  Plano de rotação · {_color('1', mode)}\n")
    for it in items:
        print(f"  • {it.account.upn}  {_color('90', '(' + it.account.kind.label + ', ' + it.reason + ')')}")
        for w in it.warnings:
            print(_color("33", f"      ! {w}"))
    print()

    if not args.apply and not args.demo:
        print("  Para executar: girachave rotate --apply --vault-url https://<cofre>.vault.azure.net\n")
        return 0

    sink = None
    if not args.demo:
        if not args.vault_url:
            print(_color("31", "  --vault-url é obrigatório: a senha nova precisa ir direto para um cofre."))
            return 1
        if not args.yes:
            typed = input(f"  Digite o nome do tenant ({snap.tenant_name}) para confirmar: ").strip()
            if typed != snap.tenant_name:
                print("  Confirmação não confere. Abortado.")
                return 1
        from .graph import Credentials
        sink = rotation.KeyVaultSink(args.vault_url, Credentials.from_env())

    results = rotation.execute(items, client, sink, AuditLog(args.log), simulate=args.demo)
    for r in results:
        mark = _color("32", "✓") if r["status"] == "ok" else _color("31", "✗")
        extra = r.get("vault_ref") or r.get("error")
        print(f"  {mark} {r['upn']}  {_color('90', str(extra))}")
    print(f"\n  Eventos gravados em {args.log} (verifique com: girachave verify-log)\n")
    return 0 if all(r["status"] == "ok" for r in results) else 1


# ------------------------------------------------------------ outros
def cmd_verify(args) -> int:
    res = verify(args.log)
    if res.ok:
        print(_color("32", f"✓ Log íntegro: {res.entries} evento(s), cadeia de hash válida."))
        return 0
    print(_color("31", f"✗ Log comprometido na linha {res.broken_at}: {res.reason}"))
    return 1


def cmd_checks(_args) -> int:
    for cid, meta in CATALOG.items():
        print(f"{_color('33', cid)}  {meta['title']}")
        print(_color("90", "        " + " · ".join(meta["controls"])))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="girachave", description="Diagnóstico, rotação e evidências para identidades "
                                "não nominais do Microsoft Entra ID.")
    p.add_argument("--version", action="version", version=f"girachave {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--demo", action="store_true", help="usa um tenant fictício (sem conexão)")
        sp.add_argument("--max-password-age", type=int, default=90, metavar="DIAS")
        sp.add_argument("--log", default=DEFAULT_LOG, help="log de auditoria encadeado (padrão: %(default)s)")

    s = sub.add_parser("scan", help="varre o tenant e gera relatório, CSV, JSON e eventos SIEM")
    common(s)
    s.add_argument("--out", default="girachave-saida", help="pasta de saída (padrão: %(default)s)")
    s.add_argument("--stale-days", type=int, default=90, metavar="DIAS")
    s.add_argument("--compare", metavar="FINDINGS_JSON", help="varredura anterior para drift (padrão: a última na pasta de saída)")
    s.add_argument("--evidence", action="store_true", help="gera pacote ZIP de evidências com manifesto SHA-256")
    s.add_argument("--teams", action="store_true", help="envia resumo ao Teams (GIRACHAVE_TEAMS_WEBHOOK)")
    s.add_argument("--contact", default="", help="texto de contato exibido no relatório")
    s.add_argument("--top", type=int, default=10, help="achados exibidos no terminal")
    s.add_argument("--fail-on", choices=[x.value for x in Severity], help="sai com código 2 se houver achado desta severidade ou pior")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rotate", help="rotaciona senhas de contas de serviço/genéricas (dry-run por padrão)")
    common(r)
    r.add_argument("--apply", action="store_true", help="executa de fato a rotação")
    r.add_argument("--vault-url", help="Azure Key Vault que recebe as novas senhas")
    r.add_argument("--only", action="append", metavar="UPN", help="restringe a uma conta (pode repetir)")
    r.add_argument("--yes", action="store_true", help="não pede confirmação interativa (automação)")
    r.set_defaults(func=cmd_rotate)

    v = sub.add_parser("verify-log", help="verifica a integridade do log de auditoria")
    v.add_argument("--log", default=DEFAULT_LOG)
    v.set_defaults(func=cmd_verify)

    c = sub.add_parser("checks", help="lista as verificações e controles mapeados")
    c.set_defaults(func=cmd_checks)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass
    if os.name == "nt":
        os.system("")  # habilita sequências ANSI no console do Windows
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrompido.")
        return 130
    except Exception as e:  # erros de Graph/rede viram mensagem limpa, sem stack com dados sensíveis
        from .graph import GraphError
        if isinstance(e, (GraphError, ValueError)):
            print(_color("31", f"Erro: {e}"), file=sys.stderr)
            return 1
        raise


if __name__ == "__main__":
    sys.exit(main())
