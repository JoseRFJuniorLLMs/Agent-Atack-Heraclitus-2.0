# Modelo de ameaças

## Objetivo de segurança

Permitir que agentes proponham testes novos sem torná-los autoridade para
declarar vulnerabilidades. O runner contínuo não oferece shell e aceita apenas
loopback. A Arena manual oferece shell livre somente depois de criar um
namespace Linux descartável. O modo remoto aceita apenas pares privados
`IP:porta` explicitamente autorizados pelo operador.

## Ativos protegidos

- serviços, arquivos e credenciais fora do laboratório;
- dados reais do HeraclitusDB;
- integridade do log de evidências;
- disponibilidade do host WSL;
- segredos do provedor LLM;
- confiabilidade do veredito e da reprodução.

## Adversários considerados

1. Saída malformada, alucinada ou deliberadamente hostil de um LLM.
2. *Prompt injection* presente em mensagens, campos ou respostas do banco.
3. Um plano que tenta alcançar rede remota, arquivos, shell ou ferramentas não
   cadastradas.
4. Um ataque que aparenta sucesso por causa de timeout, falha do harness ou
   código HTTP ambíguo.
5. Repetições que esgotam CPU, memória, descritores ou o próprio banco.
6. Uma autorização destrutiva antiga, reutilizada ou aplicável ao alvo errado.
7. Conteúdo sensível vazando para prompts, logs ou memória de campanha.
8. Um comando livre tentando escapar do namespace, consumir o host ou alcançar
   outro serviço da LAN.
9. DNS rebinding, redirecionamento, troca de IP ou porta e reutilização de uma
   janela de autorização remota.

## Controles obrigatórios

### Antes da execução

- Validar JSON estritamente e rejeitar campos desconhecidos, tipos errados,
  passos vazios e documentos acima do limite.
- Resolver e validar o destino em cada passo, inclusive redirecionamentos. O
  fato de a configuração inicial ser local não autoriza um redirect remoto.
- Usar allowlist de ferramentas e argumentos; nunca encaminhar nomes de função
  diretamente para reflexão, `eval`, shell ou subprocesso.
- Aplicar limites de passos, bytes, concorrência, tempo por chamada e tempo da
  campanha.
- Exigir autorização destrutiva com escopo, alvo, campanha e expiração, além
  de snapshot confirmado.
- Inferir mutabilidade a partir do adaptador, método e payload. Rótulos de risco
  fornecidos pelo modelo nunca rebaixam `POST`, `PUT`, `PATCH` ou `DELETE`.
- Substituir os oráculos e metadados de veredito do modelo pelo contrato de um
  seed curado; planos sem seed são obrigatoriamente diagnósticos.

### Durante a execução

- Desabilitar redirects ou revalidar cada destino resolvido.
- Limitar leitura de respostas e registrar somente amostras sanitizadas/digests.
- Tratar texto retornado pelo banco como dados, nunca como instrução para o LLM.
- Projetar memória para uma allowlist de campos tipados antes de construir o
  prompt; texto arbitrário devolvido pelo ledger é descartado.
- Cancelar a campanha quando qualquer orçamento for excedido.
- Manter IDs únicos por campanha, plano e tentativa para evitar mistura de
  evidência.

### Na Arena com shell

- Criar namespaces novos com Bubblewrap, `--unshare-all`,
  `--die-with-parent`, UID/GID internos e capabilities removidas.
- Montar somente runtimes do sistema, binário do banco, catálogo e arquivos
  selecionados do laboratório antigo; nunca montar home, `.env`, chaves ou o
  checkout completo.
- Limpar o ambiente antes do worker; as chaves dos providers permanecem no
  processo pai.
- Usar tmpfs para todo estado gravável e limites de processos, descritores,
  memória, arquivos, tempo e volume de saída.
- No modo remoto, manter o namespace sem interface externa e encaminhar cada
  porta por um socket Unix para um único IP privado literal e porta exata.
- Tratar cada descoberta de shell como candidato `INCONCLUSIVE`, nunca como
  veredito.

### No veredito

- Separar o proponente do oráculo.
- Preferir efeitos externos mensuráveis, contadores nativos, invariantes de
  ledger e equivalência de replay a texto de resposta.
- Não converter `ERROR`, timeout, `SKIP` ou ausência de telemetria em `PASS`.
- Repetir e minimizar antes de publicar `VULNERABLE`.

## Suposições e limites

- O operador controla o host e autorizou os testes.
- O kernel, Python, systemd e a conta que executa o agente não estão
  comprometidos.
- Loopback e relays exatos reduzem o raio de impacto, mas não protegem dados
  reais. Use uma base descartável para qualquer teste mutável.
- O hardening da unit reduz capacidades; ele não é uma sandbox de segurança
  completa.
- Bubblewrap depende da segurança do kernel WSL/Linux e não substitui uma VM
  dedicada para alvos de alto risco.
- Este projeto testa propriedades conhecidas e explora variações. Ele não
  prova ausência universal de vulnerabilidades.
- `heraclitus top` é telemetria operacional e não substitui IDS ou os oráculos.

## Fora de escopo

- varredura de ranges, DNS, IPs públicos ou serviços fora dos pares autorizados;
- roubo de credenciais, persistência ou evasão em sistemas de terceiros;
- shell no host, no serviço 24/7 ou fora do namespace Bubblewrap;
- testes destrutivos na instância que guarda dados reais;
- declarar um banco seguro apenas porque uma campanha passou.

## Checklist para uma campanha destrutiva

Antes de executar `config/disposable-nightly.json`, confirme todos os itens:

- [ ] instância isolada e descartável;
- [ ] snapshot criado e restauração ensaiada;
- [ ] nenhum dado ou segredo real presente;
- [ ] autorização com expiração curta emitida para esta campanha;
- [ ] limites de CPU, memória, tempo e concorrência configurados;
- [ ] observador humano disponível e procedimento de interrupção testado.
- [ ] para remoto: IP privado e portas exatas no firewall e na allowlist;
- [ ] para Arena: Bubblewrap instalado e nenhum segredo montado no namespace.
