# Modelo de IA observado

Não houve nova chamada à API para descobrir o modelo. A leitura abaixo usa só os metadados já gravados.

## O que o cliente grava

`src/openai_client.py` define `model_used` como o campo `model` da resposta, quando a biblioteca o devolve, e cai para o modelo solicitado quando esse campo vem vazio. O metadado `metadata.json` tem um único campo `model`. Não há campos separados para o modelo enviado e o modelo devolvido, e não há identificador da resposta da API.

Por isso as colunas `model_requested_separately`, `model_returned_separately` e `response_id` de `results/api_calls.csv` ficam vazias. O valor da coluna `model_recorded` é o que o arquivo original contém. Ele não foi renomeado.

## Valores registrados

| Chamada | Horário (Brasília) | `model` no metadado | HTTP | Script | Tokens entrada / saída | Parâmetros observados |
| --- | --- | --- | --- | --- | --- | --- |
| API-00 | 12/11/2026 07:40 | não há | não houve chamada | não | — | `OPENAI_API_KEY` ausente |
| API-01, repetição 1 | 12/11/2026 07:44 | `gpt-4.1` | 429 `credit_balance_exhausted` | não | não devolvidos | latência 3370 ms |
| API-02, repetição 2 | 12/11/2026 08:18 | `gpt-6-luna` | não registrado no metadado | sim | 585 / 548 | latência 6201 ms; `reasoning_effort=none`; `reasoning_tokens=0`; `temperature` 0,2 em `fase3_rep02_status.json` <!-- pragma: allowlist secret --> |
| API-03, repetição 3 | 12/11/2026 08:46 | `gpt-6-luna` | não registrado no metadado | sim | 585 / 695 | latência 6834 ms; `reasoning_effort=none`; `reasoning_tokens=0` <!-- pragma: allowlist secret --> |
| API-04, repetição 4 | 12/11/2026 08:46 | `gpt-6-luna` | não registrado no metadado | sim | 585 / 651 | latência 5625 ms; `reasoning_effort=none`; `reasoning_tokens=0` <!-- pragma: allowlist secret --> |

<!-- pragma: allowlist secret -->

O corpo da requisição não foi salvo. A temperatura 0,2 está no código do cliente e, de forma explícita, só no status da repetição 2. O hash do prompt das repetições com script é o mesmo arquivo de template preenchido com o mesmo cenário; a conferência por repetição está no `metadata.json` de cada pasta.

O identificador `gpt-6-luna` é o texto gravado no metadado das repetições 2, 3 e 4. <!-- pragma: allowlist secret --> Esta auditoria não o trata como nome oficial de catálogo além do que esses arquivos mostram, e não afirma que o modelo devolvido pela API foi outro. Essa comparação não está disponível.

O preço público usado na estimativa de custo, já citado em `docs/limitacoes.md`, é US$ 0,10 por milhão de tokens de entrada e US$ 0,50 por milhão de saída. A chamada HTTP 429 não entra no custo porque não devolveu tokens.
