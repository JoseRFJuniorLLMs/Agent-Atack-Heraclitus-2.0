# Arquitetura

## Propósito e fronteira

O Heraclitus Attack 2.0 é um laboratório de *red team* defensivo para uma
instância descartável do HeraclitusDB que o operador possui ou está autorizado
a testar. O alvo pode estar no mesmo WSL ou em um IP privado literal de uma
rede de laboratório. Ele não é um IDS, SIEM, antivírus ou monitor de intrusão
em produção.
Seu trabalho é propor experimentos, executá-los dentro de uma DSL restrita e
decidir o resultado usando evidência observável.

O comando `heraclitus top` mostra telemetria do banco. Sozinho, ele não sabe que
uma requisição pertence a uma campanha, não aplica os oráculos deste projeto e
não detecta todos os ataques. Use `heraclitus-attack` para executar e
classificar testes; use `heraclitus top` apenas como visão operacional
complementar.

## Fluxo de uma campanha tipada

```text
Recon -> Planner -> Critic -> Mutator -> Critic -> Minimizer
                              |
                    PolicyBoundary (não-LLM)
                              |
                         SafetyGate -> SafeToolExecutor -> Observation
                              |                                  |
                              + rejeita                 deterministic Oracle
                                                                 |
                                                          Finding/Memory
```

1. O reconhecimento recebe somente observações sanitizadas e capacidades
   permitidas.
2. O planejador produz um `AttackPlan` tipado. Texto livre nunca vira comando de
   sistema.
3. O crítico procura contradições, premissas sem evidência e tentativas de
   escapar do escopo.
4. `PolicyBoundary` descarta oráculos e metadados de veredito escolhidos pelo
   modelo e reaplica o contrato do seed curado. Sem seed, o plano é somente
   diagnóstico e não pode declarar vulnerabilidade.
5. `SafetyGate` valida destino, ferramenta, quantidade de passos, tempo,
   tamanho e autorização destrutiva. O risco é inferido do método e do payload,
   não apenas dos campos `risk`/`destructive` propostos.
6. `SafeToolExecutor` executa exclusivamente adaptadores conhecidos. Neste
   runner não existe ferramenta de shell, subprocesso, leitura arbitrária de
   arquivo ou rede genérica.
7. Um oráculo independente classifica a observação. O LLM que propôs o teste
   não declara o próprio sucesso.
8. Resultados e evidências limitadas são persistidos no HeraclitusDB; segredos,
   respostas integrais e raciocínio privado do modelo não são armazenados.

## Semântica dos resultados

| Resultado | Significado |
|---|---|
| `PASS` | O invariante foi observado; para ataque significa bloqueio comprovado, enquanto probes diagnósticos são rotulados como diagnóstico. |
| `VULNERABLE` | O ataque funcionou, violou um invariante e possui evidência reproduzível. |
| `INCONCLUSIVE` | A evidência não permite concluir. Nunca é contado como sucesso. |
| `ERROR` | O laboratório falhou. Não é evidência contra o banco. |
| `SKIP` | Um pré-requisito estava ausente. |

Uma descoberta só deve subir para `VULNERABLE` quando houver violação de
invariante determinístico, confirmação independente, repetição e uma
reprodução mínima. Código HTTP isolado, texto do modelo ou indisponibilidade do
alvo não satisfazem esse contrato.

## Papéis dos agentes

- `ReconAgent`: resume superfície, capacidades e resultados anteriores.
- `PlannerAgent`: gera planos estruturados dentro de um catálogo de ferramentas.
- `MutatorAgent`: produz variações limitadas de um plano já aceito.
- `CriticAgent`: tenta invalidar o plano antes da execução.
- `MinimizerAgent`: reduz uma reprodução sem ampliar permissões.
- `Coordinator`: aplica orçamentos, cria IDs únicos e controla o ciclo.

Os provedores de LLM são intercambiáveis. O `MockProvider` torna os testes
determinísticos; OpenAI Responses/Codex, Anthropic/Claude, Google/Gemini e
endpoints OpenAI-compatible podem compor um roster. `RoutingProvider` escolhe
por papel explícito e usa rodízio quando não existe rota exclusiva.
Independentemente do provedor, a saída é tratada como entrada hostil e passa
pela fronteira de política, pelo parser e pelo `SafetyGate`.

## Fluxo da Arena autônoma

```text
Codex / Claude / Gemini
          |
   ArenaAction JSON
          |
 processo pai -> Bubblewrap sem interface externa -> Bash arbitrário
                       |                         |
              clone tmpfs local       sockets Unix por porta
                                                 |
                                      IP:porta privado exato
```

A Arena é uma segunda fronteira, acionada somente de forma manual. Ela permite
shell Linux livre depois que Bubblewrap criou namespaces descartáveis, removeu
capabilities, limpou o ambiente e montou apenas o binário, o catálogo e fontes
selecionadas do laboratório 1.0. No modo remoto, o namespace continua sem
interface externa; relays do processo pai alcançam somente os endpoints
declarados.

Uma ação de shell bem-sucedida é observação de descoberta. O LLM pode registrar
um candidato, mas somente um `AttackPlan` tipado, um oráculo independente e a
reprodução tripla podem promovê-lo a `VULNERABLE`.

## Camadas de execução

| Camada | Frequência sugerida | Ambiente | Conteúdo |
|---|---:|---|---|
| Smoke determinístico | 24/7, a cada 5 min | instância local autorizada | sondas leves, limites baixos, sem mutação destrutiva |
| Exploração agentic | horária | instância descartável | novos planos e mutações com orçamento estrito |
| Arena autônoma | manual | clone tmpfs ou alvo privado descartável | Bash livre no namespace, catálogo de 28 famílias e relays exatos |
| Campanha destrutiva | noturna/manual | snapshot dedicado | falhas, corrupção simulada e carga agressiva |
| Raft real | semanal/manual | cluster descartável | partição e consenso em pelo menos três nós |

O serviço fornecido neste repositório executa somente a primeira camada. Uma
campanha destrutiva exige configuração separada, snapshot confirmado e uma
autorização de curta duração. Nunca habilite esse perfil no serviço 24/7.

## Fronteiras de rede

- `smoke`, `full` e `destructive` locais aceitam apenas loopback.
- `remote-lab` aceita somente IP literal privado/link-local presente na
  allowlist e exige token efêmero, ID de execução e confirmação manual.
- O daemon recusa `destructive`, `remote-lab` e qualquer destino remoto.
- A Arena remota traduz portas internas fixas para sockets Unix; somente o
  processo pai abre TCP para os pares exatos aprovados.

## Saída e observabilidade

`BootConsole` usa linhas no estilo do boot do Fedora e explica o significado
operacional de cada teste. Sem TTY, a cor é desativada por padrão; a unit deste
repositório define `FORCE_COLOR=1` porque o objetivo explícito é acompanhar o
serviço humano pelo `journalctl -o cat`. Os relatórios JSON continuam sem ANSI.
