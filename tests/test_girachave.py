import json
import os
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from girachave import auditlog, exports, rotation
from girachave.checks import Policy, check_account, check_app_grant, check_conditional_access, run_checks
from girachave.classifier import classify
from girachave.cli import main
from girachave.demo import build_demo_snapshot
from girachave.graph import Credentials, GraphError, _check_url
from girachave.models import (
    Account,
    AccountKind,
    AppPermissionGrant,
    ConditionalAccessPolicy,
    Finding,
    Severity,
    parse_dt,
)
from girachave.notify import _host_ok
from girachave.report import render
from girachave.scoring import compute

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)


def acc(upn, **kw):
    a = Account(id="x", upn=upn, display_name=kw.pop("display_name", ""), **kw)
    a.kind = classify(a)
    return a


class TestClassifier(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(acc("svc-backup@c.com").kind, AccountKind.SERVICE)
        self.assertEqual(acc("recepcao.matriz@c.com").kind, AccountKind.GENERIC)
        self.assertEqual(acc("joao_ext.com#EXT#@c.com").kind, AccountKind.EXTERNAL)
        self.assertEqual(acc("maria@c.com", user_type="Guest").kind, AccountKind.EXTERNAL)
        self.assertEqual(acc("ana.souza@c.com").kind, AccountKind.PERSONAL)

    def test_department_does_not_make_person_generic(self):
        self.assertEqual(acc("bruno.lima@c.com", department="TI").kind, AccountKind.PERSONAL)
        self.assertEqual(acc("joao@c.com", department="Fornecedor").kind, AccountKind.EXTERNAL)

    def test_accents(self):
        self.assertEqual(acc("x@c.com", display_name="Recepção Filial").kind, AccountKind.GENERIC)


class TestChecks(unittest.TestCase):
    def test_privileged_generic_is_critical(self):
        a = acc("admin-ti@c.com", roles=["Global Administrator"], last_password_change=NOW - timedelta(days=400))
        ids = {(f.check_id, f.severity) for f in check_account(a, NOW, Policy())}
        self.assertIn(("GC-006", Severity.CRITICAL), ids)
        self.assertIn(("GC-001", Severity.CRITICAL), ids)

    def test_personal_without_admin_has_no_findings(self):
        a = acc("ana@c.com", last_password_change=NOW - timedelta(days=900), mfa_registered=False)
        self.assertEqual(check_account(a, NOW, Policy()), [])

    def test_admin_without_phishing_resistant_mfa(self):
        a = acc("ana@c.com", roles=["Global Administrator"], mfa_registered=True, mfa_methods=["mobilePhone"])
        self.assertEqual([f.check_id for f in check_account(a, NOW, Policy())], ["GC-008"])
        a.mfa_methods = ["fido2"]
        self.assertEqual(check_account(a, NOW, Policy()), [])

    def test_stale_vendor_is_high(self):
        a = acc("fornecedor.x@c.com", last_sign_in=NOW - timedelta(days=200))
        f = [f for f in check_account(a, NOW, Policy()) if f.check_id == "GC-004"][0]
        self.assertEqual(f.severity, Severity.HIGH)

    def test_disabled_account_ignored(self):
        a = acc("svc-old@c.com", enabled=False, roles=["Global Administrator"],
                last_password_change=NOW - timedelta(days=2000))
        self.assertEqual(check_account(a, NOW, Policy()), [])

    def test_app_grants(self):
        g = AppPermissionGrant("sp", "app", "X", ["Mail.ReadWrite", "Directory.ReadWrite.All"],
                               third_party=True, verified_publisher=False, has_owner=False)
        self.assertEqual({f.check_id for f in check_app_grant(g)}, {"GC-105", "GC-106", "GC-107"})
        benign = AppPermissionGrant("sp", "app", "Y", ["User.Read.All"], has_owner=False)
        self.assertEqual(check_app_grant(benign), [])

    def test_conditional_access(self):
        good = [
            ConditionalAccessPolicy("mfa all", "enabled", requires_mfa=True, targets_all_users=True),
            ConditionalAccessPolicy("legacy", "enabled", blocks=True, targets_all_users=True, targets_legacy_auth=True),
        ]
        self.assertEqual(check_conditional_access(good), [])
        bad = [ConditionalAccessPolicy("legacy", "enabledForReportingButNotEnforced", blocks=True,
                                       targets_legacy_auth=True)]
        self.assertEqual({f.check_id for f in check_conditional_access(bad)},
                         {"GC-201", "GC-202", "GC-203", "GC-204"})

    def test_demo_covers_all_families(self):
        findings = run_checks(build_demo_snapshot(NOW))
        prefixes = {f.check_id[:4] for f in findings}
        self.assertEqual(prefixes, {"GC-0", "GC-1", "GC-2"})
        self.assertTrue(all(f.controls for f in findings))


class TestScoring(unittest.TestCase):
    def test_bounds(self):
        self.assertEqual(compute([]).value, 100)
        many = [Finding("GC-006", "t", Severity.CRITICAL, "x", "k", "", "")] * 200
        s = compute(many)
        self.assertEqual((s.value, s.grade), (0, "E"))


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "log.jsonl"
        os.environ.pop("GIRACHAVE_LOG_KEY", None)

    def tearDown(self):
        os.environ.pop("GIRACHAVE_LOG_KEY", None)
        self.dir.cleanup()

    def test_chain_and_tamper_detection(self):
        log = auditlog.AuditLog(self.path)
        for i in range(5):
            log.append("evt", {"i": i})
        self.assertTrue(auditlog.verify(self.path).ok)

        lines = self.path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[2])
        tampered["data"]["i"] = 999
        lines[2] = json.dumps(tampered)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        res = auditlog.verify(self.path)
        self.assertFalse(res.ok)
        self.assertEqual(res.broken_at, 3)

    def test_deleted_line_detected(self):
        log = auditlog.AuditLog(self.path)
        for i in range(3):
            log.append("evt", {"i": i})
        lines = self.path.read_text(encoding="utf-8").splitlines()
        del lines[1]
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(auditlog.verify(self.path).ok)

    def test_hmac_mode_requires_key(self):
        os.environ["GIRACHAVE_LOG_KEY"] = "k" * 32
        auditlog.AuditLog(self.path).append("evt")
        self.assertTrue(auditlog.verify(self.path).ok)
        os.environ["GIRACHAVE_LOG_KEY"] = "outra-chave"
        self.assertFalse(auditlog.verify(self.path).ok)

    def test_secrets_are_scrubbed(self):
        auditlog.AuditLog(self.path).append("evt", {"password": "hunter2", "nested": {"token": "abc"}})
        text = self.path.read_text(encoding="utf-8")
        self.assertNotIn("hunter2", text)
        self.assertNotIn("abc", text)


class TestRotation(unittest.TestCase):
    def test_password_strength(self):
        pw = rotation.generate_password(32)
        self.assertEqual(len(pw), 32)
        self.assertTrue(any(c.isupper() for c in pw) and any(c.islower() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw) and any(c in rotation.SYMBOLS for c in pw))
        self.assertNotEqual(pw, rotation.generate_password(32))
        with self.assertRaises(ValueError):
            rotation.generate_password(8)

    def test_plan_excludes_external_and_disabled(self):
        items = rotation.plan(build_demo_snapshot(NOW), 90)
        kinds = {i.account.kind for i in items}
        self.assertTrue(kinds <= {AccountKind.SERVICE, AccountKind.GENERIC})
        self.assertTrue(all(i.account.enabled for i in items))

    def test_vault_name(self):
        self.assertEqual(rotation.vault_secret_name("svc.x@c.com"), "girachave-svc-x--c-com")

    def test_vault_url_validation(self):
        with self.assertRaises(ValueError):
            rotation.KeyVaultSink("https://evil.example.com", Credentials("t", "c", "s"))

    def test_simulated_run_never_logs_password(self):
        with tempfile.TemporaryDirectory() as d:
            log = auditlog.AuditLog(Path(d) / "l.jsonl")
            items = rotation.plan(build_demo_snapshot(NOW), 90)
            res = rotation.execute(items, None, None, log, simulate=True)
            self.assertTrue(all(r["status"] == "ok" for r in res))
            self.assertTrue(auditlog.verify(log.path).ok)


class TestSecurityControls(unittest.TestCase):
    def test_graph_url_allowlist(self):
        _check_url("https://graph.microsoft.com/v1.0/users")
        for bad in ("http://graph.microsoft.com/v1.0", "https://evil.com/x", "https://graph.microsoft.com.evil.com/"):
            with self.assertRaises(GraphError):
                _check_url(bad)

    def test_credentials_repr_hides_secret(self):
        self.assertNotIn("s3cr3t", repr(Credentials("t", "c", "s3cr3t")))

    def test_teams_webhook_allowlist(self):
        _host_ok("https://contoso.webhook.office.com/webhookb2/abc")
        with self.assertRaises(ValueError):
            _host_ok("https://attacker.example/webhook")

    def test_csv_injection_neutralized(self):
        f = Finding("GC-001", "=HYPERLINK(\"x\")", Severity.LOW, "+cmd", "k", "-1", "@SUM(1)")
        csv_text = exports.findings_csv([f])
        self.assertIn("'=HYPERLINK", csv_text)
        self.assertIn("'+cmd", csv_text)
        self.assertIn("'@SUM", csv_text)

    def test_report_escapes_html(self):
        snap = build_demo_snapshot(NOW)
        snap.tenant_name = "<script>alert(1)</script>"
        html = render(snap, run_checks(snap), compute([]))
        self.assertNotIn("<script>alert(1)", html)
        self.assertIn("&lt;script&gt;", html)


class TestExports(unittest.TestCase):
    def test_drift(self):
        snap = build_demo_snapshot(NOW)
        findings = run_checks(snap)
        prev = json.loads(exports.findings_json(snap, findings[1:], compute(findings[1:])))
        d = exports.drift(prev, findings)
        self.assertEqual(len(d["new"]), 1)
        self.assertEqual(d["resolved"], [])

    def test_siem_lines_are_json(self):
        snap = build_demo_snapshot(NOW)
        lines = exports.siem_jsonl(snap, run_checks(snap)).splitlines()
        self.assertTrue(lines)
        for line in lines:
            self.assertEqual(json.loads(line)["observer"]["product"], "girachave")

    def test_parse_dt(self):
        self.assertEqual(parse_dt("2024-01-02T03:04:05.1234567Z").microsecond, 123456)
        self.assertIsNone(parse_dt("0001-01-01T00:00:00Z"))
        self.assertIsNone(parse_dt(None))


class TestCli(unittest.TestCase):
    def test_scan_demo_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            out, log = Path(d) / "out", str(Path(d) / "audit.jsonl")
            self.assertEqual(main(["scan", "--demo", "--out", str(out), "--log", log, "--evidence"]), 0)
            for name in ("relatorio.html", "findings.json", "findings.csv", "inventario.csv", "siem.jsonl"):
                self.assertTrue((out / name).exists(), name)
            pack = next(out.glob("evidencias-*.zip"))
            with zipfile.ZipFile(pack) as z:
                manifest = json.loads(z.read("MANIFEST.json"))
                self.assertIn("relatorio.html", manifest["files"])
            # segunda varredura gera drift
            main(["scan", "--demo", "--out", str(out), "--log", log])
            self.assertTrue((out / "drift.json").exists())
            self.assertEqual(main(["scan", "--demo", "--out", str(out), "--log", log, "--fail-on", "critica"]), 2)
            self.assertEqual(main(["verify-log", "--log", log]), 0)

    def test_rotate_dry_run_without_demo_needs_env(self):
        for n in ("GIRACHAVE_TENANT_ID", "GIRACHAVE_CLIENT_ID", "GIRACHAVE_CLIENT_SECRET"):
            os.environ.pop(n, None)
        with self.assertRaises(SystemExit):
            main(["rotate"])


if __name__ == "__main__":
    unittest.main()
