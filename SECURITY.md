# Política de segurança

## Reportar uma vulnerabilidade

Encontrou uma falha no Girachave? Por favor **não abra uma issue pública**.
Use o recurso [Private vulnerability reporting](https://github.com/rmoraes23/girachave/security/advisories/new)
do GitHub. Respondemos em até 5 dias úteis.

## Modelo de segurança da ferramenta

| Risco | Controle |
|---|---|
| Vazamento das credenciais do app | Lidas só de variáveis de ambiente (nunca argumentos de CLI); `repr` mascarado; nunca registradas em log |
| Abuso de permissões | Diagnóstico usa apenas permissões *Read*; escrita só para rotação, opcional |
| Exposição de senhas rotacionadas | Geradas com `secrets` (CSPRNG), mantidas só em memória e gravadas direto no Azure Key Vault; o log recebe só a referência da versão |
| Lockout por rotação | Dry-run por padrão; confirmação explícita; cofre gravado **antes** da troca no Entra ID |
| SSRF / exfiltração do token | Allowlist de hosts para Graph, login, Key Vault e webhook do Teams; somente HTTPS |
| Adulteração de evidências | Log encadeado por SHA-256 (ou HMAC-SHA256 com `GIRACHAVE_LOG_KEY`); pacote de evidências com manifesto de hashes |
| CSV injection | Células iniciadas por `= + - @` são neutralizadas |
| XSS no relatório | Todo conteúdo dinâmico é escapado; relatório sem JavaScript e com CSP `default-src 'none'` |
| Supply chain | Zero dependências de terceiros (biblioteca padrão do Python) |

## Dados do cliente

As saídas (`girachave-saida/`, `girachave-audit.jsonl`, `evidencias-*.zip`) contêm
informações do tenant e estão no `.gitignore`. Trate-as como confidenciais.
