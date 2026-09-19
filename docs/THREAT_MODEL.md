# Modelo de ameaças

## Objetivo de segurança

Permitir que agentes proponham testes novos sem transformar um LLM em um shell,
um cliente de rede irrestrito ou uma autoridade para declarar vulnerabilidades.
O alvo autorizado é exclusivamente loopback (`127.0.0.0/8`, `::1` ou
`localhost`) e deve ser uma instância do HeraclitusDB preparada pelo operador.

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

### Durante a execução

- Desabilitar redirects ou revalidar cada destino resolvido.
- Limitar leitura de respostas e registrar somente amostras sanitizadas/digests.
- Tratar texto retornado pelo banco como dados, nunca como instrução para o LLM.
- Cancelar a campanha quando qualquer orçamento for excedido.
- Manter IDs únicos por campanha, plano e tentativa para evitar mistura de
  evidência.

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
- Loopback reduz o raio de impacto, mas não protege dados reais. Use uma base
  descartável para qualquer teste mutável.
- O hardening da unit reduz capacidades; ele não é uma sandbox de segurança
  completa.
- Este projeto testa propriedades conhecidas e explora variações. Ele não
  prova ausência universal de vulnerabilidades.
- `heraclitus top` é telemetria operacional e não substitui IDS ou os oráculos.

## Fora de escopo

- varredura de IPs ou serviços remotos;
- roubo de credenciais, persistência ou evasão em sistemas de terceiros;
- shell gerado por modelo;
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

