# Política de segurança

Este repositório é um laboratório defensivo para ambientes que você possui ou
tem autorização explícita para testar. O executor recusa destinos que não sejam
loopback e não oferece shell, subprocesso, acesso arbitrário a arquivos ou uma
ferramenta genérica de rede ao modelo.

Não publique tokens, credenciais, dumps ou respostas integrais do banco em uma
issue. Para relatar uma falha do laboratório, abra um *security advisory* privado
no GitHub com uma reprodução mínima e metadados sanitizados.

Um resultado `VULNERABLE` exige uma violação de invariante reproduzida e
confirmada por um oráculo independente. `ERROR`, `FAIL` ou `INCONCLUSIVE` não
significam que o HeraclitusDB possua uma vulnerabilidade.
