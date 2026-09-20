# Arena autônoma

A Arena é o modo manual para dar Bash arbitrário a agentes LLM sem entregar o
host inteiro. Ela serve para descobrir combinações que o catálogo fixo ainda
não cobre. Não é o processo 24/7: o serviço `systemd` continua usando somente o
executor tipado e sem shell.

## Dois modos de alvo

```text
local-clone
LLM -> Bash no Bubblewrap -> HeraclitusDB novo em /arena/data (tmpfs)

remote-exact-relay
LLM -> Bash no Bubblewrap -> 127.0.0.1:porta -> socket Unix -> IP:porta autorizado
```

No modo local, o worker inicia uma cópia nova do binário do HeraclitusDB dentro
da arena. No modo remoto, nenhum servidor é iniciado no namespace: cada porta
local possui um relay host-side para exatamente um endereço privado declarado.
O agente não recebe uma interface capaz de varrer a LAN.

## Liberdade e fronteiras

Dentro do namespace o agente pode combinar comandos Bash, `curl`, Python e as
ferramentas Linux montadas em `/usr`, `/bin`, `/lib` e `/lib64`. Também recebe:

- o catálogo de 28 famílias em `/opt/catalog/attack-families.json`;
- arquivos selecionados e somente leitura do projeto 1.0 em `/opt/legacy`;
- um diretório gravável novo em `/arena`;
- endereços do banco em variáveis `HERACLITUS_*`.

A fronteira Bubblewrap usa novos namespaces de usuário, mount, PID, IPC, UTS,
cgroup e rede, remove capabilities, limpa o ambiente, limita processos,
descritores, memória, arquivos, tempo e saída, e encerra o grupo de processos
de comandos que excedem o prazo. Diretórios pessoais, `.env`, chaves SSH e o
checkout completo não são montados.

Isso contém o agente em relação ao host, mas não torna seguro apontá-lo para
dados reais. O alvo deve ser sempre um clone descartável.

## Pré-requisitos no WSL/Linux

```bash
sudo apt-get update
sudo apt-get install bubblewrap

cd /mnt/d/DEV/Agent-Atack-Heraclitus-2.0
.venv/bin/python -m pip install -e '.[dev]'
test -x ../HeraclitusDB/target/release/heraclitus-server
```

O modo de shell não roda diretamente no Windows porque Bubblewrap e namespaces
são recursos Linux. Em uma máquina Windows, execute esse comando dentro do
WSL2. O runner tipado normal pode rodar em Python no Windows.

## Clone local descartável

`config/arena.json` usa `MockProvider`, portanto demonstra a arena offline:

```bash
cd /mnt/d/DEV/Agent-Atack-Heraclitus-2.0
export HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN="arena-$(date +%s)"

FORCE_COLOR=1 .venv/bin/heraclitus-attack arena \
  --config config/arena.json \
  --snapshot-id tmpfs-$(date +%Y%m%d-%H%M%S) \
  --i-understand-isolated-shell
```

Para usar agentes vivos, copie
`config/arena-multi-provider.example.json`, selecione modelos disponíveis na
sua conta e defina `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` e `GEMINI_API_KEY`.

## Alvo remoto descartável

Copie `config/remote-lab.example.json` para um arquivo não versionado e troque
o IP de exemplo pelo IP privado literal do laboratório. O mesmo IP deve estar
em `allowed_remote_hosts`, `allowed_targets` e `targets`.

```bash
export HERACLITUS_REMOTE_LAB_TOKEN="remote-$(date +%s)"
export HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN="clone-$(date +%s)"

FORCE_COLOR=1 .venv/bin/heraclitus-attack arena \
  --config config/remote-lab.json \
  --snapshot-id clone-remoto-42 \
  --remote-run-id janela-2026-09-20-01 \
  --i-understand-isolated-shell \
  --i-understand-remote-lab
```

DNS e IP público são recusados. Os dois tokens são lidos do ambiente do
processo pai; o ambiente é limpo antes de entrar na arena e as chaves dos
providers não são entregues ao shell.

## Protocolo e resultado

Cada ação do modelo é JSON estruturado com comando, hipótese, justificativa e
um candidato opcional. O worker devolve código de saída, timeout, saúde do alvo,
tamanho, truncamento e SHA-256 de stdout/stderr. A saída completa é limitada.

`exit=0` significa apenas que o comando Linux executou. Uma hipótese descoberta
fica `INCONCLUSIVE`; nunca vira vulnerabilidade pelo texto do modelo. Para
promover a `VULNERABLE`, converta o candidato em `AttackPlan`, associe um
oráculo determinístico, reproduza três vezes e minimize a reprodução.

Relatórios são gravados como
`reports/.../<arena-id>-arena.json`. O diretório tmpfs e todos os processos são
descartados ao encerrar a sessão.

## Interrupção

Use `Ctrl+C` para interromper. Bubblewrap usa `--die-with-parent`; o worker
também termina o grupo de processos do banco e de cada comando. Se precisar
confirmar que não restou sessão:

```bash
pgrep -af 'arena_worker.py|heraclitus-arena' || true
```

