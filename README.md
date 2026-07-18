# Girachave

**Rotação de credenciais do Entra ID, no piloto automático.**
**Entra ID credential rotation, on autopilot.**

🔗 [rmoraes23.github.io/girachave](https://rmoraes23.github.io/girachave/)

---

## 🇧🇷 Português

### O que é

Girachave é uma landing page de validação para um micro SaaS de segurança focado em **Microsoft Entra ID**. A proposta: descobrir, rotacionar e documentar contas genéricas, contas de serviço e credenciais compartilhadas que ficam fora do fluxo passwordless (Windows Hello, FIDO2) — e que costumam ser o ponto cego em auditorias de segurança (SOX, ISO 27001).

### Problema

- Contas de serviço e credenciais compartilhadas não entram no fluxo passwordless do Entra ID e ficam com senha estática.
- Acessos de fornecedores via VPN raramente têm ciclo formal de revisão.
- Provar rotação e revisão de acesso numa auditoria vira trabalho manual de última hora.

### Status do projeto

🚧 **Fase de validação.** Este repositório contém apenas a landing page, usada para:
- Testar a proposta de valor com profissionais de TI/segurança
- Capturar e-mails de lista de espera (via Google Sheets)
- Apoiar entrevistas de descoberta de cliente

Nenhum produto foi desenvolvido ainda.

### Stack

- HTML/CSS/JS puro (sem build step) — arquivo único, `index.html`
- Captura de e-mail via [Google Apps Script](https://developers.google.com/apps-script) conectado a uma planilha do Google Sheets
- Publicado com GitHub Pages

### Estrutura

```
girachave/
├── index.html    → landing page completa (hero, problema, como funciona, preço, waitlist)
└── README.md     → este arquivo
```

### Como rodar localmente

Não há dependências — basta abrir o `index.html` no navegador. Para testar o envio de e-mails, é necessário ter um endpoint do Apps Script configurado e referenciado na constante `WAITLIST_ENDPOINT` dentro do arquivo.

### Autor

Desenvolvido por um especialista em Cibersegurança, GRC e IAM, com experiência prévia em auditoria fiscal — unindo a visão de compliance/controles com execução técnica em automação (Python, PowerShell, Power Automate, Microsoft Graph API).

---

## 🇬🇧 English

### What it is

Girachave is a validation landing page for a security-focused micro SaaS built around **Microsoft Entra ID**. The pitch: discover, rotate, and document generic accounts, service accounts, and shared credentials that fall outside the passwordless flow (Windows Hello, FIDO2) — and that are typically the blind spot in security audits (SOX, ISO 27001).

### Problem

- Service accounts and shared credentials don't fit into Entra ID's passwordless flow, so they're stuck with static passwords.
- Vendor VPN access rarely has a formal review cycle.
- Proving rotation and access review during an audit turns into last-minute manual work.

### Project status

🚧 **Validation phase.** This repository currently contains only the landing page, used to:
- Test the value proposition with IT/security professionals
- Capture waitlist emails (via Google Sheets)
- Support customer discovery interviews

No product has been built yet.

### Stack

- Plain HTML/CSS/JS (no build step) — single `index.html` file
- Email capture via a [Google Apps Script](https://developers.google.com/apps-script) endpoint writing to a Google Sheet
- Deployed with GitHub Pages

### Structure

```
girachave/
├── index.html    → full landing page (hero, problem, how it works, pricing, waitlist)
└── README.md     → this file
```

### Running locally

No dependencies — just open `index.html` in a browser. To test email submission, you'll need your own Apps Script endpoint configured and referenced in the `WAITLIST_ENDPOINT` constant inside the file.

### Author

Built by a Cybersecurity, GRC & IAM specialist with a background in tax/fiscal auditing — combining a compliance and controls mindset with hands-on automation (Python, PowerShell, Power Automate, Microsoft Graph API).
