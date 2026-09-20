# Matriz de ataques simulados

Este projeto exercita uma instância de desenvolvimento/pré-produção do
HeraclitusDB pertencente ao operador. Todos os marcadores, ferramentas negadas
e callbacks são sintéticos. Nenhum vetor autoriza atacar terceiros ou usar o
perfil destrutivo contra dados reais.

## Serviço smoke 24/7

| Família | Simulação | Evidência determinística |
|---|---|---|
| Disponibilidade | alcance TCP do listener gRPC | booleano tipado de reachability; somente diagnóstico |
| REST | leitura limitada de health | status HTTP limitado; somente diagnóstico |
| Traversal | caminho duplamente codificado tentando sair do namespace de bundles | status de negação; nunca conteúdo refletido |
| Parser MCP | JSON propositalmente inválido | rejeição HTTP sem execução de ferramenta |
| Abuso de ferramenta | chamada a `heraclitus_redteam_forbidden_probe` | negação HTTP mais contador upstream antes/depois |
| SSRF induzido por agente | callback loopback sintético dentro da ferramenta proibida | contador upstream deve permanecer sem delta |

Os agentes LLM mutam primeiro esses vetores de ataque, não as duas sondas de
diagnóstico. A etapa `PolicyBoundary` remove qualquer escolha de oráculo feita
pelo modelo e reaplica o contrato do seed curado.

## Janela controlada em cópia descartável

| Família | Simulação | Condição operacional |
|---|---|---|
| Limite OTLP | documento JSON sintético superdimensionado | snapshot + token, pois usa POST válido |
| Confusão de batch | JSON-RPC misturando chamada benigna e chamada negada | snapshot + token |
| Prompt injection indireto | documento hostil como dado de uma ferramenta sintética proibida | upstream deve permanecer sem efeito |
| Plano customizado | reprodução escrita pelo operador | mesmo gate, allowlist, orçamento e reprodução tripla |

`POST`, `PUT`, `PATCH`, `DELETE` e requisições de leitura com corpo são
classificados pela semântica real e exigem autorização destrutiva. As únicas
exceções do smoke são o JSON inválido, que não pode invocar método, e a
ferramenta sintética proibida com nome e marcador exatos.

## Critério de descoberta

Uma resposta inesperada começa como `FAIL`. Ela só vira `VULNERABLE` quando um
oráculo independente produz a mesma evidência tipada em três execuções. Timeout,
listener desligado, autenticação ausente ou falta de contador resultam em
`INCONCLUSIVE`, nunca em falso `PASS`.

Vetores que dependem de topologia real — isolamento multitenant, consenso Raft,
crash/recovery e corrupção de disco — devem usar fixtures descartáveis próprias
do HeraclitusDB e execução manual. Eles não pertencem ao daemon smoke.

## Catálogo da Arena: 28 famílias

A Arena entrega o arquivo `config/attack-families.json` aos agentes Codex,
Claude, Gemini ou locais. O catálogo orienta exploração nova sem prescrever um
script único:

| Grupo | IDs | Famílias |
|---|---|---|
| Verdade temporal | T01–T04 | rollback de snapshot; colisão/gap/reuso de LSN; epoch pinning; falsificação de Merkle/timestamp |
| Durabilidade | D01–D03 | WAL rasgado/truncado; crash em fronteiras de commit; restore com policy/índice adulterado |
| Consenso e falhas distribuídas | C01–C03 | split brain/joint consensus; retry storm/phantom commit; cancelamento/falha parcial |
| Autorização e isolamento | A01–A04 | TOCTOU/cache obsoleto; confused deputy/capability laundering; tenant/agente/namespace; escopo de credencial/downgrade |
| Agentes e memória | L01–L03 | poisoning persistente/RAG; confiança multiagente forjada; relabeling de ferramenta/ambiguidade de método |
| Protocolos e parsing | P01–P04 | diferencial JSON/JSON-RPC; smuggling HTTP/gRPC; Unicode/normalização; traversal/SSRF/redirect |
| Recursos | R01–R03 | depth/compression/cardinality bombs; slowloris/descritores; complexidade algorítmica/Hume AST |
| Semântica e evidência | S01–S04 | mutação ampla; desaparecimento/adulteração de auditoria; side channel temporal; sucesso 2xx com estado errado |

Os agentes podem encadear famílias e criar payloads em tempo real. `exit=0`,
crash ou texto persuasivo do modelo continuam sendo apenas observações. Um
candidato precisa migrar para um teste tipado com invariante, oráculo e
reprodução antes de ser reportado como vulnerabilidade.
