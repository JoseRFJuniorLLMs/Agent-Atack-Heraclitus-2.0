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
.venv/bin/heraclitus-attack doctor --config config/smoke.json
```

`doctor` deve recusar qualquer endpoint que não seja loopback. Não contorne
essa validação.

## 3. Teste interativo

```bash
cd /mnt/d/DEV/Agent-Atack-Heraclitus-2.0
FORCE_COLOR=1 .venv/bin/heraclitus-attack run --config config/smoke.json
```

Em um terminal, as linhas aparecem no estilo do boot do Fedora:

- `[ OK ]`: o ataque não funcionou e o oráculo comprovou a proteção;
- `[ VULNERÁVEL ]`: o ataque funcionou e o banco tem vulnerabilidade reproduzível;
- `[ INCERTO ]`: faltou evidência; não é aprovação;
- `[ ERRO ]`: o laboratório falhou; não é diagnóstico do banco.

## 4. Instalação do serviço

A unit versionada assume o checkout em
`/mnt/d/DEV/Agent-Atack-Heraclitus-2.0`. Para outro caminho, crie um override em
vez de editar a unit instalada.

```bash
mkdir -p ~/.config/systemd/user
cp deploy/systemd/heraclitus-attack-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now heraclitus-attack-agent.service
```

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

O journal recebe eventos sem cor e adequados a coleta estruturada. Para a visão
humana colorida, execute o comando interativo da seção 3. Se quiser apenas que
o próprio `journalctl` colore metadados, use `SYSTEMD_COLORS=1`; não force ANSI
dentro dos eventos JSON.

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

## 7. Campanhas agentic e destrutivas

O serviço 24/7 não deve apontar para
`config/disposable-nightly.json`. Para uma campanha exploratória, clone/restaure
uma instância descartável, gere a autorização exigida pelo `SafetyGate`, execute
uma vez sob supervisão e descarte/restaure o alvo ao terminar.

Se um teste reportar `VULNERABLE`, pare a promoção automática, preserve os
digests e IDs da campanha, repita três vezes e gere uma reprodução mínima antes
de abrir um advisory privado.

