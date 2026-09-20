# Agentes Codex, Claude, Gemini e locais

O projeto suporta vários providers na mesma campanha. Cada provider recebe o
mesmo contrato JSON estruturado; nenhum deles decide sozinho se o banco é
vulnerável.

## Providers disponíveis

| `kind` | API | Credencial típica |
|---|---|---|
| `openai-responses` | OpenAI Responses, incluindo modelos Codex disponíveis na conta | `OPENAI_API_KEY` |
| `anthropic` | Anthropic Messages com saída estruturada | `ANTHROPIC_API_KEY` |
| `gemini` | Gemini `generateContent` com JSON Schema | `GEMINI_API_KEY` |
| `openai-compatible` | endpoint local/compatível, como um servidor de modelos no loopback | configurável |
| `mock` | determinístico e offline para testes/CI | nenhuma |

O nome do modelo é configuração do operador porque disponibilidade e nomes
dependem da conta. O arquivo `config/arena-multi-provider.example.json` contém
um roster pronto para editar.

## Exemplo multi-provider

```json
{
  "providers": [
    {
      "name": "codex",
      "kind": "openai-responses",
      "base_url": "https://api.openai.com/v1",
      "model": "gpt-5.2-codex",
      "api_key_env": "OPENAI_API_KEY",
      "timeout_seconds": 60.0,
      "roles": ["recon", "minimizer"]
    },
    {
      "name": "claude",
      "kind": "anthropic",
      "base_url": "https://api.anthropic.com",
      "model": "MODELO_CLAUDE_DA_SUA_CONTA",
      "api_key_env": "ANTHROPIC_API_KEY",
      "timeout_seconds": 60.0,
      "roles": ["planner", "critic"]
    },
    {
      "name": "gemini",
      "kind": "gemini",
      "base_url": "https://generativelanguage.googleapis.com/v1beta",
      "model": "gemini-2.5-flash",
      "api_key_env": "GEMINI_API_KEY",
      "timeout_seconds": 60.0,
      "roles": ["mutator"]
    }
  ]
}
```

Defina as chaves somente na sessão que executará a campanha:

```bash
export OPENAI_API_KEY='...'
export ANTHROPIC_API_KEY='...'
export GEMINI_API_KEY='...'
```

Não grave chaves em JSON, Git, prompt ou relatório.

## Roteamento

Os papéis do pipeline são `recon`, `planner`, `critic`, `mutator` e
`minimizer`. Quando um papel aparece em `roles`, ele usa apenas os providers
designados. Se mais de um provider tiver o papel, ocorre rodízio entre eles.

Pedidos sem uma rota explícita usam rodízio entre todo o roster. É o caso do
papel `arena-operator` no exemplo: Codex, Claude e Gemini escolhem ações em
sequência. O nome do provider utilizado é registrado em cada etapa do
relatório.

## Codex do aplicativo e Codex pela API

Este chat no aplicativo Codex e o processo `heraclitus-attack` são contextos
separados. Trocar esta conversa para Astra ou outro modelo não fornece uma API
key ao programa e não é necessário para habilitar o roster. Para usar Codex
como agente do laboratório, configure um modelo Codex disponível via OpenAI
Responses e `OPENAI_API_KEY`.

Da mesma forma, assinar ou abrir Claude/Gemini em outro aplicativo não fornece
automaticamente as chaves Anthropic/Google ao WSL.

## Estrutura e falha fechada

- OpenAI recebe `text.format` com JSON Schema e `store=false`.
- Claude recebe `output_config.format` com JSON Schema.
- Gemini recebe `responseMimeType=application/json` e
  `responseJsonSchema`.
- A resposta ainda é validada localmente; campos desconhecidos e envelopes
  inválidos são recusados.
- Timeout, recusa ou erro de provider não vira `PASS` nem `VULNERABLE`.
- Credenciais dos providers ficam no processo pai e não são passadas ao shell
  Bubblewrap.

## Teste inicial

Comece com uma única ação e um clone vazio:

```bash
cp config/arena-multi-provider.example.json config/arena-live.json
# Edite somente IDs de modelo e limites desejados.

export HERACLITUS_ATTACK_DESTRUCTIVE_TOKEN="arena-$(date +%s)"
.venv/bin/heraclitus-attack arena \
  --config config/arena-live.json \
  --snapshot-id provider-smoke-01 \
  --max-actions 1 \
  --i-understand-isolated-shell
```

Depois confira o campo `provider` de cada passo no relatório da arena. Aumente
o orçamento somente depois de validar custo, timeout e formato dos três
providers.

