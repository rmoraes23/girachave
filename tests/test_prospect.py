import tempfile
import unittest
from pathlib import Path

from girachave.leads import read_csv, write_csv, Lead
from girachave.prospect import ProspectError, assess, normalize_domain
from girachave.prospect_report import email_draft, render_company, render_index


def fake_dns(records):
    def dns(name, rtype):
        return records.get((name, rtype), [])
    return dns


def realm(ns="Managed", viral=None):
    return lambda d: {"NameSpaceType": ns, "IsViral": viral, "FederationBrandName": "Contoso"}


def probe(**kw):
    base = {"https_ok": True, "cert_days_left": 200, "http_redirects": True, "error": "",
            "headers": {"strict-transport-security": "max-age=1", "content-security-policy": "frame-ancestors 'self'",
                        "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"}}
    base.update(kw)
    return lambda d: base


GOOD = {
    ("empresa.com.br", "MX"): ["0 empresa-com-br.mail.protection.outlook.com."],
    ("empresa.com.br", "TXT"): ['"v=spf1 include:spf.protection.outlook.com -all"'],
    ("_dmarc.empresa.com.br", "TXT"): ['"v=DMARC1; p=reject; rua=mailto:d@empresa.com.br"'],
    ("selector1._domainkey.empresa.com.br", "TXT"): ['"v=DKIM1; k=rsa; " "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx"'],
    ("selector2._domainkey.empresa.com.br", "TXT"): ['"v=DKIM1; p="'],  # chave revogada
}


class TestNormalize(unittest.TestCase):
    def test_variants(self):
        for v in ("https://www.Empresa.com.br/contato", "empresa.com.br", "www.empresa.com.br:443"):
            self.assertEqual(normalize_domain(v), "empresa.com.br")
        idn = normalize_domain("padaria-são-joão.com.br")
        self.assertTrue(idn.startswith("xn--") and idn.endswith(".com.br"))

    def test_rejects_garbage(self):
        for v in ("", "localhost", "http://", "a b.com", "../etc/passwd"):
            with self.assertRaises(ProspectError):
                normalize_domain(v)


class TestAssess(unittest.TestCase):
    def test_well_configured_domain(self):
        r = assess("empresa.com.br", "Empresa", dns=fake_dns(GOOD), realm=realm(), probe=probe())
        self.assertEqual(r.findings, [])
        self.assertTrue(r.uses_m365)
        self.assertEqual(r.mail_provider, "Microsoft 365")
        self.assertEqual(r.dkim_selectors, ["selector1"])

    def test_spoofable_domain(self):
        recs = {("loja.com.br", "MX"): ["10 mx.loja.com.br."],
                ("loja.com.br", "TXT"): ['"v=spf1 +all"']}
        r = assess("loja.com.br", dns=fake_dns(recs), realm=realm("Unknown"),
                   probe=probe(https_ok=False, error="x"))
        ids = {f.check_id for f in r.findings}
        self.assertTrue({"PX-001", "PX-004", "PX-005", "PX-006"} <= ids)
        self.assertFalse(r.uses_m365)

    def test_dmarc_none_and_multiple_spf(self):
        recs = dict(GOOD)
        recs[("empresa.com.br", "TXT")] = ['"v=spf1 -all"', '"v=spf1 include:x -all"']
        recs[("_dmarc.empresa.com.br", "TXT")] = ['"v=DMARC1; p=none"']
        ids = {f.check_id for f in assess("empresa.com.br", dns=fake_dns(recs), realm=realm(), probe=probe()).findings}
        self.assertEqual(ids, {"PX-002", "PX-004"})

    def test_null_mx_skips_email_checks(self):
        r = assess("site.com.br", dns=fake_dns({("site.com.br", "MX"): ["0 ."]}), realm=realm("Unknown"),
                   probe=probe())
        self.assertEqual(r.mx, [])
        self.assertEqual(r.findings, [])

    def test_viral_tenant_is_not_m365(self):
        r = assess("empresa.com.br", dns=fake_dns(GOOD), realm=realm("Managed", viral=True), probe=probe())
        self.assertFalse(r.uses_m365)

    def test_unverifiable_tls_is_not_a_finding(self):
        r = assess("empresa.com.br", dns=fake_dns(GOOD), realm=realm(),
                   probe=probe(https_ok=None, headers={}, error="TLS: unable to get local issuer certificate"))
        self.assertNotIn("PX-006", {f.check_id for f in r.findings})

    def test_failures_do_not_crash(self):
        def boom(*a):
            raise OSError("rede fora")
        r = assess("empresa.com.br", dns=boom, realm=boom, probe=boom)
        self.assertTrue(r.errors)

    def test_opportunity_rewards_m365_and_risk(self):
        good = assess("empresa.com.br", dns=fake_dns(GOOD), realm=realm(), probe=probe())
        bad = assess("loja.com.br", dns=fake_dns({("loja.com.br", "MX"): ["10 mx.loja.com.br."]}),
                     realm=realm(), probe=probe())
        self.assertGreater(bad.opportunity, good.opportunity)


class TestOutputs(unittest.TestCase):
    def test_report_and_email_escape_and_content(self):
        recs = {("x.com.br", "MX"): ["10 mx.x.com.br."]}
        r = assess("x.com.br", "<b>Evil</b>", dns=fake_dns(recs), realm=realm(), probe=probe())
        html = render_company(r, "contato", "Fulano")
        self.assertNotIn("<b>Evil</b>", html)
        self.assertIn("&lt;b&gt;Evil", html)
        self.assertIn("Nenhum sistema foi acessado", html)
        mail = email_draft(r, "Fulano")
        self.assertIn("remover", mail)
        self.assertIn("Microsoft 365", mail)
        self.assertIn("x.com.br", render_index([r]))

    def test_leads_csv_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "l.csv"
            write_csv([Lead("=cmd", "https://www.a.com.br", "a.com.br"), Lead("B", "b.com.br", "b.com.br")], p)
            self.assertIn("'=cmd", p.read_text(encoding="utf-8-sig"))
            leads = read_csv(p)
            self.assertEqual([l.dominio for l in leads], ["a.com.br", "b.com.br"])

    def test_csv_with_only_site_column(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "l.csv"
            p.write_text("site\nhttps://www.c.com.br\nlixo\nc.com.br\n", encoding="utf-8")
            self.assertEqual([l.dominio for l in read_csv(p)], ["c.com.br"])


if __name__ == "__main__":
    unittest.main()
