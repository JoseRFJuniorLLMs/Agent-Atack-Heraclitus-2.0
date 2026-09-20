# Laboratório remoto: Linux/Windows para WSL/Linux

O atacante e o HeraclitusDB podem estar na mesma WSL ou em máquinas separadas.
O requisito é que o banco remoto seja uma instância privada, descartável e
explicitamente autorizada.

## Topologias suportadas

```text
1. Mesma máquina
Windows -> WSL2 -> Agent Attack -> clone HeraclitusDB no namespace

2. Atacante Linux
Linux Agent Attack -> rede privada/VPN -> Linux ou WSL com HeraclitusDB de teste

3. Atacante Windows
Windows Python runner -> rede privada/VPN -> Linux ou WSL com HeraclitusDB de teste

4. Atacante Windows com shell autônomo
Windows -> WSL2 Bubblewrap -> relays exatos -> Linux ou WSL com HeraclitusDB de teste
```

O runner normal (`run`) é multiplataforma. A Arena com Bash livre requer
Linux/WSL2 no lado atacante.

## Preparar o alvo

Use uma VM, WSL ou host de laboratório separado do banco real:

1. restaure um snapshot sem dados e segredos de produção;
2. faça os listeners aceitarem conexões somente na interface privada;
3. no firewall, permita apenas o IP da máquina atacante e somente as portas
   realmente usadas;
4. use credenciais de curta duração e sem acesso a outros ambientes;
5. confirme o procedimento de restauração antes de testar;
6. mantenha telemetria e logs fora do volume que será descartado.

Nunca publique essas portas na Internet e nunca use a configuração remota para
o HeraclitusDB primário.

## Configuração do atacante

Crie um arquivo local a partir do exemplo:

```bash
cd /mnt/d/DEV/Agent-Atack-Heraclitus-2.0
cp config/remote-lab.example.json config/remote-lab.json
chmod 600 config/remote-lab.json
```

Substitua `192.168.56.20` pelo IP privado literal do alvo em três lugares:

- `runtime.safety.allowed_remote_hosts`;
- `runtime.safety.allowed_targets`;
- cada campo de `targets`.

Nomes DNS, ranges, curingas e IPs públicos não são aceitos. A correspondência
é exata por IP e porta.

Valide sem enviar carga ofensiva:

```bash
.venv/bin/heraclitus-attack show-config --config config/remote-lab.json
.venv/bin/heraclitus-attack doctor --config config/remote-lab.json
```

## Runner remoto tipado

O modo abaixo usa somente os adaptadores HTTP/MCP/TCP conhecidos e o gate de
segurança:

```bash
export HERACLITUS_REMOTE_LAB_TOKEN="janela-$(date +%s)"
export HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN="snapshot-$(date +%s)"

.venv/bin/heraclitus-attack run \
  --config config/remote-lab.json \
  --remote-run-id lab-2026-09-20-01 \
  --snapshot-id snapshot-42 \
  --i-understand-remote-lab
```

O perfil `remote-lab` é recusado pelo daemon 24/7. Cada janela precisa de token,
ID auditável e confirmação manual. Operações mutáveis também exigem snapshot e
o token destrutivo.

## Arena remota com Bash livre

A Arena cria uma rede vazia. Dentro dela, `127.0.0.1:17475`, `17474`, `18080`,
`18787`, `14318` e `19000` são listeners locais que atravessam sockets Unix. O
processo pai conecta cada socket a somente um `IP:porta` aprovado. Assim, um
comando livre não consegue trocar o destino ou enumerar a sub-rede.

Use os dois reconhecimentos explícitos:

```bash
.venv/bin/heraclitus-attack arena \
  --config config/remote-lab.json \
  --snapshot-id snapshot-42 \
  --remote-run-id lab-2026-09-20-01 \
  --i-understand-isolated-shell \
  --i-understand-remote-lab
```

## Alternativa por túnel SSH

Para uma campanha tipada, você também pode manter todos os destinos como
loopback e criar túneis de portas para o host remoto. Exemplo para REST e gRPC:

```bash
ssh -N \
  -L 17475:127.0.0.1:7475 \
  -L 17474:127.0.0.1:7474 \
  usuario@IP_PRIVADO_DO_LAB
```

Nesse caso, crie uma configuração de runner apontando para `127.0.0.1:17475` e
`127.0.0.1:17474`. O túnel não substitui snapshot, credencial efêmera ou
autorização do alvo. Para a Arena remota, prefira os relays exatos nativos.

## Credenciais e evidência

Credenciais opcionais são lidas de `HERACLITUS_AGENT_TOKEN`,
`HERACLITUS_CORE_USERNAME` e `HERACLITUS_CORE_PASSWORD` somente após o plano
passar pelo gate. Elas não entram no plano, prompt ou relatório. Sem a
credencial exigida, o teste resulta em `INCONCLUSIVE`, não em falso `PASS`.

Depois da campanha, revogue os tokens, preserve somente relatórios sanitizados
e restaure ou destrua a instância de teste.

