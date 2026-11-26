# Girachave

**Segurança de identidades não nominais no Microsoft Entra ID — diagnóstico, rotação e evidência de auditoria.**

🔗 Site: [rmoraes23.github.io/girachave](https://rmoraes23.github.io/girachave/) ·
📄 [Relatório de exemplo](https://rmoraes23.github.io/girachave/exemplo/relatorio.html)

Contas de serviço, contas genéricas/compartilhadas, acessos de fornecedores e **identidades não-humanas** (apps OAuth e service principals) ficam fora do fluxo passwordless, raramente são revisadas e são o primeiro alvo de atacantes — e a primeira coisa que o auditor pede.

O Girachave descobre essas identidades, aponta os riscos com o controle de conformidade correspondente, rotaciona senhas direto para o cofre e gera evidência à prova de adulteração.

---

## O que ele faz

| Área | Recursos |
|---|---|
| **Descoberta** | Classifica automaticamente contas de serviço, genéricas, de terceiros e convidados B2B |
| **Contas não nominais** | Idade de senha, senha que nunca expira, sem MFA, dormentes, nunca usadas, sem responsável, papel de admin |
| **Identidades não-humanas (NHI)** | Apps com permissões críticas (`Directory.ReadWrite.All`, `RoleManagement.*`…), apps de terceiros lendo e-mail/arquivos, segredos expirados, vencendo ou longos demais, apps sem certificado, apps privilegiados sem dono |
| **Acesso Condicional** | Autenticação legada liberada, admins sem MFA, MFA não universal, políticas só em modo relatório, admins sem MFA resistente a phishing (FIDO2/passkey) |
| **Rotação segura** | CSPRNG, 32 caracteres, entrega direta no Azure Key Vault, dry-run por padrão, confirmação explícita |
| **Evidência** | Log encadeado por hash (SHA-256/HMAC), pacote ZIP com manifesto SHA-256, relatório HTML executivo + técnico, plano de ação 30/60/90 |
| **Monitoramento contínuo** | Drift entre varreduras (novos × resolvidos), alertas no Microsoft Teams, eventos JSONL para Sentinel/Splunk/Elastic/Wazuh, código de saída para pipelines |
| **Conformidade** | Cada achado mapeado para ISO 27001:2022, CIS v8, NIST CSF 2.0, PCI DSS 4.0, LGPD, CMN/BACEN 4.893 e SOX ITGC |

Lista completa: `girachave checks` (19 verificações).

## Demonstração em 30 segundos (sem tenant)

Requer Python 3.10+. **Sem dependências externas.**

```powershell
git clone https://github.com/rmoraes23/girachave
cd girachave
python -m girachave scan --demo --evidence
```

Abra `girachave-saida/relatorio.html`. Para simular a rotação:

```powershell
python -m girachave rotate --demo
python -m girachave verify-log
```

## Uso em um tenant real

### 1. App registration (somente leitura)

No Entra ID, crie um *App registration* e conceda **permissões de aplicação** do Microsoft Graph (com consentimento de admin):

| Permissão | Para quê |
|---|---|
| `User.Read.All` | inventário de contas |
| `Directory.Read.All` | papéis de diretório e responsáveis |
| `AuditLog.Read.All` | último login (requer Entra ID P1) |
| `UserAuthenticationMethod.Read.All` | métodos de MFA registrados |
| `Application.Read.All` | segredos, certificados e permissões de apps |
| `Policy.Read.All` | políticas de Acesso Condicional |

Só para rotação (opcional): `User-PasswordProfile.ReadWrite.All` + papel *Key Vault Secrets Officer* no cofre.

> Sem P1, o Girachave segue funcionando e avisa quais verificações foram puladas.

### 2. Credenciais por variável de ambiente

Nunca passe segredos como argumento de linha de comando.

```powershell
$env:GIRACHAVE_TENANT_ID = "<tenant-id>"
$env:GIRACHAVE_CLIENT_ID = "<client-id>"
$env:GIRACHAVE_CLIENT_SECRET = "<segredo>"
$env:GIRACHAVE_LOG_KEY = "<chave longa e aleatória>"   # opcional: log com HMAC
```

### 3. Comandos

```powershell
python -m girachave scan --evidence                      # diagnóstico + pacote de evidências
python -m girachave scan --teams                         # + alerta no Teams (GIRACHAVE_TEAMS_WEBHOOK)
python -m girachave scan --fail-on critica               # sai com código 2 se houver risco crítico
python -m girachave rotate                               # plano de rotação (dry-run)
python -m girachave rotate --apply --vault-url https://meu-cofre.vault.azure.net
python -m girachave verify-log                           # confere a integridade do log
```

Saídas em `girachave-saida/`: `relatorio.html`, `findings.json`, `findings.csv`, `inventario.csv`, `siem.jsonl`, `drift.json` e `evidencias-*.zip`.

Para monitoramento contínuo, agende `scan --teams` no Agendador de Tarefas, Azure Automation ou GitHub Actions — cada execução é comparada com a anterior.

## Segurança da própria ferramenta

Menor privilégio, segredos só em memória, allowlist de hosts (anti-SSRF), CSV injection neutralizada, relatório com CSP e sem JavaScript, log imutável e zero dependências de terceiros. Detalhes em [SECURITY.md](SECURITY.md).

## Estrutura

```
girachave/
├── index.html, assets/       → landing page (autodiagnóstico, captação de leads)
├── exemplo/relatorio.html    → relatório gerado em modo demo (para prospecção)
├── girachave/                → ferramenta Python
│   ├── cli.py                → comandos scan / rotate / verify-log / checks
│   ├── collector.py, graph.py→ coleta somente leitura via Microsoft Graph
│   ├── classifier.py         → classificação de contas
│   ├── checks.py             → 19 verificações + mapeamento de controles
│   ├── scoring.py, report.py → score de exposição e relatório HTML
│   ├── rotation.py           → rotação segura + Azure Key Vault
│   ├── auditlog.py           → log encadeado por hash
│   ├── exports.py, notify.py → CSV/JSON, SIEM, evidências, drift, Teams
│   └── demo.py               → tenant fictício para demonstrações
└── tests/                    → 31 testes (python -m unittest discover -s tests)
```

## Landing page

HTML/CSS/JS sem build, publicada no GitHub Pages. Inclui autodiagnóstico interativo de 8 perguntas (respostas ficam no navegador), formulário com honeypot anti-bot e consentimento LGPD, e CSP restritiva. O e-mail é enviado a um Google Apps Script (`WAITLIST_ENDPOINT` em `assets/site.js`) que grava numa planilha; os campos `empresa`, `score` e `origem` também são enviados — atualize o script para gravá-los, se quiser.

## Autor

Especialista em Cibersegurança, GRC e IAM, com 10 anos de experiência no setor fiscal — unindo a visão de compliance e controles com automação (Python, PowerShell, Power Automate, Microsoft Graph API).
