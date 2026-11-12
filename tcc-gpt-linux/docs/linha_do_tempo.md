# Linha do tempo

Horários em America/Sao_Paulo (UTC−3). Quando a fonte só tem UTC, a conversão está indicada. Três séries distintas: infraestrutura, chamadas à API e execuções. Os identificadores se cruzam em `results/experimental_runs.csv`.

## A. Tentativas de infraestrutura

Fonte: `results/infrastructure_attempts.csv`.

| ID | Quando | Região | Resultado | Motivo | Recursos | Limpeza |
| --- | --- | --- | --- | --- | --- | --- |
| INF-01 | não disponível | não disponível | falha | segredos ausentes | não disponível | não disponível |
| INF-02 | não disponível | não disponível | falha | segredos ausentes | não disponível | não disponível |
| INF-03 | não disponível | não disponível | falha | SCP negou EC2 | 0 na narrativa | não se aplica |
| INF-04 | 12/11/2026 06:14 | não confirmada no JSON | falha | SCP `p-xikt6vmn` negou a sonda EC2; `apply` não rodou | 0 | não se aplica |
| INF-05 | 12/11/2026 06:52 | `us-east-2` | sucesso | — | 18 | 14/14 itens com `ok=true` em `cleanup-fase3.json`; o JSON de limpeza não tem horário |

INF-01, INF-02 e INF-03 existem só na frase de `scenarios/CVE-2024-38428/evidence/STATUS.md` (“Tentativas 1–2: secrets ausentes” e o agrupamento das tentativas 3 e 4). Não há JSON próprio. INF-04 vem de `execucao_bloqueada.json`. INF-05 vem de `before.json`: instância `i-04da3315297ec6c04`, AMI pública `ami-096d6538c463eb1db`, VPC `vpc-0d85cf02d23b63442`, NAT `nat-055a7c92e17eb05b8`, tipo `t3.small`.

## B. Chamadas à API

Fonte: `results/api_calls.csv`. API-00 não é chamada: a chave estava ausente e `generate` não rodou (`fase3_generate_blocked.json`, 07:40).

| ID | Quando | Modelo no metadado | HTTP | Script |
| --- | --- | --- | --- | --- |
| API-01 | 07:44 | `gpt-4.1` | 429 | não |
| API-02 | 08:18 | `gpt-6-luna` | não registrado | sim, repetição 2 <!-- pragma: allowlist secret --> |
| API-03 | 08:46 | `gpt-6-luna` | não registrado | sim, repetição 3 <!-- pragma: allowlist secret --> |
| API-04 | 08:46 | `gpt-6-luna` | não registrado | sim, repetição 4 <!-- pragma: allowlist secret --> |

<!-- pragma: allowlist secret -->

A chamada 429 é falha de API. Não conta como script gerado.

## C. Execuções experimentais

Fonte: `results/experimental_runs.csv`. Conjunto histórico `EXP-CVE-2024-38428-rep01` a `rep04`. AMI e instância, quando preenchidas, são as da INF-05.

| ID | Chamada | Script | Estado inicial | Validação registrada | Execução | Classificação deste protocolo |
| --- | --- | --- | --- | --- | --- | --- |
| EXP-…-rep01 | API-01 | não houve | — | — | não executado | NAO_EXECUTADO |
| EXP-…-rep02 | API-02 | SHA-256 `98155f6a…ae61` | `1.21.4-1ubuntu4` | reprovada, depois aprovada | SSM `Success` | INCONCLUSIVO |
| EXP-…-rep03 | API-03 | SHA-256 `f9f980f5…4abf` | `1.21.4-1ubuntu4` restaurado com `prepare.sh --apply` | aprovada | SSM `Success` | INCONCLUSIVO |
| EXP-…-rep04 | API-04 | SHA-256 `6095fa79…1c22` | `1.21.4-1ubuntu4` restaurado com `prepare.sh --apply` | aprovada | SSM `Success` | INCONCLUSIVO |

`recorded_remediation_success` permanece 1 nas repetições 2, 3 e 4: a verificação por versão observou `1.21.4-1ubuntu4.5`, que satisfaz o mínimo `1.21.4-1ubuntu4.1`. A classificação INCONCLUSIVO é outra coluna. Ela registra que a mesma EC2 executou os três scripts e que não há teste funcional do `wget` nem saída de scanner. Esse rótulo não reescreve o ledger.

Comandos SSM de execução: repetição 2 `e574d8bc-9ae6-4e75-bce4-d492636cadf4`; repetição 3 `7b10b131-3e0e-4592-bffe-6af2f071a40c`; repetição 4 `1e72edbe-9671-419d-99bc-36e32336dabc`. Preparação: `5efc87f2-17d8-4ffb-bd51-fb86b6213ef5` e `74060d56-31d9-46db-8a10-1f3423bd05c4`.

A reexecução controlada, se for autorizada, receberá identificadores novos e não será somada a estas linhas sem essa distinção.
