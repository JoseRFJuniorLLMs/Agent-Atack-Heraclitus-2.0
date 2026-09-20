# Política de segurança

Este repositório é um laboratório defensivo para ambientes que você possui ou
tem autorização explícita para testar. O runner normal usa ferramentas tipadas
e recusa destinos fora do loopback. O perfil manual `remote-lab` permite apenas
IPs privados literais em allowlist exata, com token efêmero e ID auditável.

A Arena é a única exceção de shell: ela oferece Bash arbitrário dentro de
Bubblewrap descartável, sem capabilities, arquivos pessoais ou interface de
rede externa. No modo remoto, sockets por porta alcançam somente os pares
`IP:porta` autorizados. Essa contenção não autoriza usar dados reais nem
terceiros; a Arena deve apontar apenas para clones descartáveis.

Saídas do LLM são hostis: seus metadados de oráculo são descartados e métodos
mutáveis exigem snapshot e token com base na semântica real, não no rótulo de
risco fornecido pelo modelo.

Chaves OpenAI, Anthropic, Gemini e credenciais do HeraclitusDB devem existir
somente no ambiente do processo pai. Elas não são montadas no shell da Arena e
não devem aparecer em configuração versionada, prompts ou relatórios.

Não publique tokens, credenciais, dumps ou respostas integrais do banco em uma
issue. Para relatar uma falha do laboratório, abra um *security advisory* privado
no GitHub com uma reprodução mínima e metadados sanitizados.

Um resultado `VULNERABLE` exige uma violação de invariante reproduzida e
confirmada por um oráculo independente. `ERROR`, `FAIL` ou `INCONCLUSIVE` não
significam que o HeraclitusDB possua uma vulnerabilidade.
