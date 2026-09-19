# Arquitetura

## Propósito e fronteira

O Heraclitus Attack 2.0 é um laboratório de *red team* defensivo para uma
instância local do HeraclitusDB que o operador possui ou está autorizado a
testar. Ele não é um IDS, SIEM, antivírus ou monitor de intrusão em produção.
Seu trabalho é propor experimentos, executá-los dentro de uma DSL restrita e
decidir o resultado usando evidência observável.

O comando `heraclitus top` mostra telemetria do banco. Sozinho, ele não sabe que
uma requisição pertence a uma campanha, não aplica os oráculos deste projeto e
não detecta todos os ataques. Use `heraclitus-attack` para executar e
classificar testes; use `heraclitus top` apenas como visão operacional
complementar.

## Fluxo de uma campanha

```text
ReconAgent -> PlannerAgent -> CriticAgent -> SafetyGate -> SafeToolExecutor
                                     |                   |
                                     | rejeita           v
                                     +------------> Observation
                                                           |
                                                independent Oracle
                                                           |
                                                    Finding/Memory
```

1. O reconhecimento recebe somente observações sanitizadas e capacidades
   permitidas.
2. O planejador produz um `AttackPlan` tipado. Texto livre nunca vira comando de
   sistema.
3. O crítico procura contradições, premissas sem evidência e tentativas de
   escapar do escopo.
4. `SafetyGate` valida destino, ferramenta, quantidade de passos, tempo,
   tamanho e autorização destrutiva.
5. `SafeToolExecutor` executa exclusivamente adaptadores conhecidos. Não existe
   ferramenta de shell, subprocesso, leitura arbitrária de arquivo ou rede
   genérica.
6. Um oráculo independente classifica a observação. O LLM que propôs o teste
   não declara o próprio sucesso.
7. Resultados e evidências limitadas são persistidos no HeraclitusDB; segredos,
   respostas integrais e raciocínio privado do modelo não são armazenados.

## Semântica dos resultados

| Resultado | Significado |
|---|---|
| `PASS` | O ataque executou e não venceu a proteção segundo o oráculo. |
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
determinísticos; o provedor compatível com OpenAI fala com um endpoint
configurado pelo operador. Independentemente do provedor, a saída é tratada
como entrada hostil e passa pelo mesmo parser e `SafetyGate`.

## Camadas de execução

| Camada | Frequência sugerida | Ambiente | Conteúdo |
|---|---:|---|---|
| Smoke determinístico | 24/7, a cada 5 min | instância local autorizada | sondas leves, limites baixos, sem mutação destrutiva |
| Exploração agentic | horária | instância descartável | novos planos e mutações com orçamento estrito |
| Campanha destrutiva | noturna/manual | snapshot dedicado | falhas, corrupção simulada e carga agressiva |
| Raft real | semanal/manual | cluster descartável | partição e consenso em pelo menos três nós |

O serviço fornecido neste repositório executa somente a primeira camada. Uma
campanha destrutiva exige configuração separada, snapshot confirmado e uma
autorização de curta duração. Nunca habilite esse perfil no serviço 24/7.

## Saída e observabilidade

Em um TTY, `BootConsole` usa linhas no estilo do boot do Fedora e explica o
significado operacional de cada teste. Sem TTY, a cor é desativada por padrão.
No serviço, eventos estruturados são enviados ao journal, o que permite
filtragem e retenção sem depender de sequências ANSI. `FORCE_COLOR=1` pode ser
usado interativamente, mas não deve ser gravado na unit de produção.

