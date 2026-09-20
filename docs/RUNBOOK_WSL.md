# Runbook WSL e systemd

Este runbook instala o agente como serviço de usuário no WSL. O serviço fica
ativo 24/7, mas executa apenas o perfil `smoke`: testes pequenos, autorizados e
loopback-only. Ele não executa campanhas destrutivas continuamente.

## 1. Pré-requisitos

No PowerShell, confirme que o WSL usa systemd em `/etc/wsl.conf`:

```ini
[boot]
systemd=true
```

Depois reinicie apenas o WSL com `wsl --shutdown` e abra a distribuição de
novo. No Linux, valide:

```bash
systemctl --user is-system-running
python3 --version
```

O HeraclitusDB e sua API de agente devem escutar somente em loopback. Ajuste as
portas nos arquivos de configuração se sua instalação usar valores diferentes.

## 2. Instalação isolada

```bash
cd /mnt/d/DEV/Agent-Atack-Heraclitus-2.0
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
sudo apt-get install bubblewrap
.venv/bin/heraclitus-attack doctor --config config/smoke.json
```

`doctor` deve recusar qualquer endpoint que não seja loopback, exceto no perfil
manual `remote-lab` com IP privado literal explicitamente permitido. Não
contorne essa validação.

## 3. Teste interativo

```bash
cd /mnt/d/DEV/Agent-Atack-Heraclitus-2.0
FORCE_COLOR=1 .venv/bin/heraclitus-attack run --config config/smoke.json
```

Em um terminal, as linhas aparecem no estilo do boot do Fedora:

- `[ OK ]`: o ataque não funcionou e o oráculo comprovou a proteção; em uma
  sonda diagnóstica, a própria linha diz somente qual propriedade foi observada;
- `[ VULNERÁVEL ]`: o ataque funcionou e o banco tem vulnerabilidade reproduzível;
- `[ INCERTO ]`: faltou evidência; não é aprovação;
- `[ ERRO ]`: o laboratório falhou; não é diagnóstico do banco.

## 4. Instalação do serviço

A unit versionada assume o checkout em
`/mnt/d/DEV/Agent-Atack-Heraclitus-2.0`. Para outro caminho, crie um override em
vez de editar a unit instalada.

```bash
mkdir -p ~/.config/systemd/user
mkdir -p ~/.config/heraclitus-attack
cp config/agent.env.example ~/.config/heraclitus-attack/agent.env
chmod 600 ~/.config/heraclitus-attack/agent.env
cp deploy/systemd/heraclitus-attack-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now heraclitus-attack-agent.service
```

O arquivo `agent.env` fica fora do repositório. Preencha-o somente se usar um
provider LLM ou endpoints autenticados; nunca coloque segredos no JSON da
campanha nem nos prompts.

Para manter serviços de usuário ativos quando não houver uma sessão aberta:

```bash
sudo loginctl enable-linger "$USER"
```

Essa alteração é opcional no WSL: se a distribuição inteira for encerrada,
nenhum serviço Linux continua executando até o WSL iniciar novamente.

## 5. Estado e logs

```bash
systemctl --user status heraclitus-attack-agent.service --no-pager -l
journalctl --user -u heraclitus-attack-agent.service -n 100 --no-pager
journalctl --user -fu heraclitus-attack-agent.service -o cat
```

O journal recebe as linhas explicativas com ANSI porque a unit define
`FORCE_COLOR=1`. Use `-o cat` para enxergar o formato semelhante ao boot do
Fedora; os relatórios JSON gravados em `reports/` permanecem sem códigos de cor.

Para observar o banco em outro terminal:

```bash
cd /mnt/d/DEV/HeraclitusDB
./target/release/heraclitus top
```

`heraclitus top` não detecta nem classifica invasões sozinho. Compare a
telemetria com os IDs e vereditos emitidos pelo `heraclitus-attack`.

## 6. Operação

```bash
systemctl --user restart heraclitus-attack-agent.service
systemctl --user stop heraclitus-attack-agent.service
systemctl --user start heraclitus-attack-agent.service
systemctl --user disable --now heraclitus-attack-agent.service
```

Para mudar caminho, intervalo ou configuração com um override:

```bash
systemctl --user edit heraclitus-attack-agent.service
```

Exemplo:

```ini
[Service]
WorkingDirectory=/caminho/do/checkout
ExecStart=
ExecStart=/caminho/do/checkout/.venv/bin/heraclitus-attack daemon --config /caminho/do/checkout/config/smoke.json
```

Depois rode `systemctl --user daemon-reload` e reinicie o serviço.

## 7. Arena autônoma local

Não coloque a Arena no serviço. Abra uma janela supervisionada e um clone
tmpfs novo:

```bash
cd /mnt/d/DEV/Agent-Atack-Heraclitus-2.0
export HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN="arena-$(date +%s)"
FORCE_COLOR=1 .venv/bin/heraclitus-attack arena \
  --config config/arena.json \
  --snapshot-id tmpfs-$(date +%Y%m%d-%H%M%S) \
  --i-understand-isolated-shell
```

O `MockProvider` faz uma verificação offline. Para Codex, Claude e Gemini,
copie `config/arena-multi-provider.example.json`, selecione os IDs de modelo e
exporte as três chaves. Veja `docs/ARENA.md` e `docs/PROVIDERS.md`.

## 8. Campanhas agentic, remotas e destrutivas

O serviço 24/7 não deve apontar para
`config/disposable-nightly.json`. Para uma campanha exploratória, clone/restaure
uma instância descartável, gere a autorização exigida pelo `SafetyGate`, execute
uma vez sob supervisão e descarte/restaure o alvo ao terminar.

O gate infere mutabilidade pelo método e pelo payload. Um plano que declare
`risk=safe` ainda exige snapshot e token se tentar uma operação mutável. O LLM
também não escolhe os critérios de sucesso: a fronteira de política reaplica o
contrato de oráculo do seed curado antes da execução.

Se um teste reportar `VULNERABLE`, pare a promoção automática, preserve os
digests e IDs da campanha, repita três vezes e gere uma reprodução mínima antes
de abrir um advisory privado.

O perfil `remote-lab` e a Arena remota também são exclusivamente manuais. Eles
exigem IP privado literal em allowlist, token remoto efêmero, `--remote-run-id`
e, para mutação, snapshot e token destrutivo. O alvo remoto deve ser uma cópia
descartável; consulte `docs/REMOTE_LAB.md`.
