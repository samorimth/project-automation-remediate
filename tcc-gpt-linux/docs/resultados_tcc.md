# Resultados

A CVE aprovada é a **CVE-2024-38428 (`wget`)**, no Ubuntu 24.04 LTS (`noble`). A Fase 6 só lê as evidências já gravadas. Não houve nova chamada à API da OpenAI, nem novo recurso AWS. `results/experiments.json` e os scripts em `generated_scripts/` não foram reescritos.

## Versão corrigida oficial

Consulta feita em 12 de novembro de 2026:

| Fonte | O que foi lido | Versão para o Ubuntu 24.04 |
| --- | --- | --- |
| [Ubuntu CVE Tracker](https://ubuntu.com/security/CVE-2024-38428) | página consultada | `Fixed in 1.21.4-1ubuntu4.1` para `noble` |
| [OSV da USN-6852-1](https://api.osv.dev/v1/vulns/USN-6852-1) | JSON consultado | intervalo corrigido em `1.21.4-1ubuntu4.1`; `1.21.4-1ubuntu4` está entre as versões afetadas |
| [USN-6852-1](https://ubuntu.com/security/notices/USN-6852-1) | página HTML | **pendente**: a consulta devolveu HTTP 503 e, na repetição, expirou |

O critério do laboratório continua o do tracker e do registro OSV: versão instalada `>= 1.21.4-1ubuntu4.1`. A versão observada depois das três execuções foi `1.21.4-1ubuntu4.5`, entregue pelo repositório `noble-updates` / `noble-security`. Essa versão é posterior ao primeiro pacote corrigido. A [USN-8543-2](https://ubuntu.com/security/notices/USN-8543-2), de 20 de agosto de 2026, publica `wget 1.21.4-1ubuntu4.5` para o Ubuntu 24.04. No trecho em que recapitula avisos anteriores, essa USN diz que a CVE-2024-38428 só afetou o Ubuntu 14.04 LTS. Essa frase não substitui o tracker nem o OSV da USN-6852-1, que tratam `1.21.4-1ubuntu4` em `noble` como afetada. Os resultados abaixo não foram reclassificados por causa dessa frase.

## O que cada número representa

Os indicadores não usam o mesmo denominador.

| Conjunto | Quantidade | Fonte |
| --- | --- | --- |
| Tentativa local sem chamada à API | 1, em 12 de novembro de 2026, 07:40 (horário de Brasília): `OPENAI_API_KEY` ausente e `generate` não executado | `scenarios/CVE-2024-38428/evidence/fase3_generate_blocked.json` |
| Chamadas à API | 4 | `results/experiments.json` |
| Chamada com HTTP 429 `insufficient_quota` | 1 (repetição 1, `gpt-4.1`, 3370 ms, sem script) | `results/CVE-2024-38428/rep01.json` e `fase3_generate_status.json` |
| Scripts gerados | 3 (repetições 2, 3 e 4) | `generated_scripts/CVE-2024-38428/rep02` a `rep04` |
| Eventos de validação no ledger | 4: uma reprovação e três aprovações | `results/experiments.json` |
| `validation.json` preservado | 3, todos aprovados; o da primeira passagem da repetição 2 foi sobrescrito | pasta de cada repetição |
| Execuções SSM do script gerado | 3, status `Success` | `ssm-execute.json` de cada repetição |
| Remediações comprovadas | 3 | `verify_before_execute.json` e `verify_after_execute.json` |
| Execução recusada sem SSM | 1, a repetição 1, porque não havia script aprovado | `fase3_generate_status.json` (`ssm_command_sent: false`) |

As repetições 2, 3 e 4 usaram gpt-6-luna, com `reasoning_effort=none` e 0 tokens de raciocínio. O cliente envia `temperature` 0,2. <!-- pragma: allowlist secret -->

## Chamadas e execuções

Horários em Brasília (UTC−3).

| Rep. | Chamada | Latência | Tokens entrada / saída | Validação no ledger | Execução | Antes | Depois |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 07:44, HTTP 429 | 3370 ms | não devolvidos | sem script | recusada localmente | — | — |
| 2 | 08:18 | 6201 ms | 585 / 548 | reprovada, depois aprovada | SSM `Success` | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.5` |
| 3 | 08:46 | 6834 ms | 585 / 695 | aprovada | SSM `Success` | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.5` |
| 4 | 08:46 | 5625 ms | 585 / 651 | aprovada | SSM `Success` | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.5` |

Identificadores SSM da execução: repetição 2 `e574d8bc-9ae6-4e75-bce4-d492636cadf4`; repetição 3 `7b10b131-3e0e-4592-bffe-6af2f071a40c`; repetição 4 `1e72edbe-9671-419d-99bc-36e32336dabc`. O stdout de cada uma contém `Unpacking wget (1.21.4-1ubuntu4.5) over (1.21.4-1ubuntu4)`.

A verificação independente, separada desse stdout, registrou `vulneravel_por_versao` antes e `corrigido_por_versao` depois, sempre contra o mínimo `1.21.4-1ubuntu4.1`. Na repetição 2 há dois comandos de verificação depois da execução, `9b36e271-b5ce-4b6c-bf05-04a4e260ee7c` (`verify_after_execute.json`) e `84f69511-870f-401a-b3af-573f73fa3d83` (`verify_independent.json`). Os dois observam `1.21.4-1ubuntu4.5`.

## Taxas

Calculadas por `python -m src.main report` a partir dos arquivos acima. Estão em `results/summary.csv`.

| Métrica | Numerador / denominador | Valor |
| --- | --- | --- |
| Sintaxe (`bash -n`) entre scripts gerados | 3 / 3 | 1,0000 |
| ShellCheck sem erro bloqueante, entre scripts gerados | 3 / 3 | 1,0000 |
| Aprovação de segurança entre eventos de validação do ledger | 3 / 4 | 0,7500 |
| Aprovação no `validation.json` final preservado | 3 / 3 | 1,0000 |
| Remediação comprovada entre execuções | 3 / 3 | 1,0000 |
| Remediação comprovada entre chamadas à API | 3 / 4 | 0,7500 |

Os avisos ShellCheck não entram na taxa de reprovação. O `validation.json` preservado registra 0 erros e, respectivamente, 1, 1 e 3 achados de nível info (SC1091 nas repetições 2 e 3; SC2317 na repetição 4).

As três gerações com resposta somam 1755 tokens de entrada e 1894 de saída. A latência média dessas três é 6220 ms. A chamada recusada por cota fica na série de latência e fora da série de tokens.

Gráficos em `results/charts/`:

- `taxa_correcao_sintatica.png`
- `analise_estatica.png`
- `aprovacao_seguranca.png`
- `taxa_remediacao.png`
- `tempo_geracao.png`
- `consumo_tokens.png`

## Validador e restauração do estado vulnerável

A primeira validação da repetição 2 terminou com código 1. `results/CVE-2024-38428/fase3_rep02_status.json` registra o motivo: o checklist tratou `$PACKAGE` e `||` como pacotes fora do escopo. O script atribuía `PACKAGE="wget"` e usava `apt-get install` com `"$PACKAGE" || apt-get install`. O validador passou a resolver atribuições simples no início da linha e a ignorar operadores da shell (`src/script_validator.py`). A segunda passagem aprovou o mesmo script. O `validation.json` da primeira passagem não foi preservado; o arquivo atual é o da segunda, de 12 de novembro de 2026, 08:19 (horário de Brasília).

Na Fase 6 os três `remediation.sh` foram relidos com essa versão do validador. O laudo novo está em `results/fase6/revalidation/` e não substitui o log original. Os três passaram de novo, com os mesmos totais de achados info, e o bit de execução dos scripts originais não foi alterado. Essa releitura não recria a reprovação da primeira passagem, porque o código do checklist já é o posterior à correção.

A repetição 2 começou no `wget` `1.21.4-1ubuntu4` provado na Fase 2. Não houve novo `prepare.sh` antes dela. As repetições 3 e 4 só foram geradas depois de `prepare.sh --apply`, que reinstalou o `.deb` `1.21.4-1ubuntu4` com o SHA-256 conferido e devolveu `vulneravel_por_versao`. Comandos SSM: `5efc87f2-17d8-4ffb-bd51-fb86b6213ef5` e `74060d56-31d9-46db-8a10-1f3423bd05c4`.

## Provisionamento e limpeza

A tentativa 4 de provisionamento não executou `apply`: a sonda EC2 foi negada pelo SCP `p-xikt6vmn` (`results/CVE-2024-38428/execucao_bloqueada.json`). As tentativas 1 a 3 estão só na narrativa de `scenarios/CVE-2024-38428/evidence/STATUS.md`. A tentativa 5, em `us-east-2`, criou 18 recursos e a instância `i-04da3315297ec6c04` (`evidence/before.json`, 06:52, horário de Brasília).

Depois das repetições, a pilha com tag `Project=tcc-gpt-linux` e `ExperimentId=fase-2-wget` foi destruída. `evidence/cleanup-fase3.json` lista 14 itens removidos, entre eles a instância, o NAT `nat-055a7c92e17eb05b8`, o EIP, o Internet Gateway e a VPC `vpc-0d85cf02d23b63442`. O JSON de limpeza não traz horário próprio.

## Limitações destes resultados

- Uma CVE, um pacote, três scripts executados e uma chamada sem script.
- A redução de esforço manual não foi medida. Não há comparação entre modelos.
- A taxa de 3/3 no `validation.json` final não é a taxa da primeira passagem. A primeira passagem da repetição 2 está no ledger como reprovação, sem o JSON daquele laudo.
- `results/CVE-2024-38428/rep02.json`, `rep03.json` e `rep04.json` guardam só o último evento de cada repetição. A série completa está em `experiments.json` e `experiments.csv`.
- O preço público citado em `docs/limitacoes.md` (US$ 0,10 por milhão de tokens de entrada e US$ 0,50 por milhão de saída) coloca as três gerações com resposta em cerca de US$ 0,001. Isso não é fatura.

## Classificação pelo protocolo novo

`results/experimental_runs.csv` separa o booleano histórico `recorded_remediation_success` da classificação deste protocolo. As repetições 2, 3 e 4 continuam com remediação 1, porque a versão subiu de `1.21.4-1ubuntu4` para `1.21.4-1ubuntu4.5`. A classificação é INCONCLUSIVO: a mesma EC2 executou os três scripts e não há teste funcional do `wget` nem saída de scanner. A repetição 1 é NAO_EXECUTADO. Essas três taxas de 3/3 descrevem este conjunto, não outras CVEs.

As tabelas separadas são `results/infrastructure_attempts.csv`, `results/api_calls.csv` e `results/experimental_runs.csv`. A chamada HTTP 429 está só na tabela de API. Os gráficos com os nomes em inglês pedidos para o TCC estão ao lado dos gráficos em português: `syntax_success.png`, `remediation_success.png`, `security_approval.png`, `generation_time.png`, `token_usage.png` e `cost.png`. O gráfico de custo usa a tabela pública e omite a chamada sem tokens.
