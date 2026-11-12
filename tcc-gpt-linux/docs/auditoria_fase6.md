# Auditoria da Fase 6 — CVE-2024-38428

Consolidação feita em 12 de novembro de 2026, só com arquivos do repositório. Não houve `terraform apply`, `terraform destroy`, chamada à API da OpenAI nem alteração de `results/experiments.json`, `results/experiments.csv` ou dos scripts em `generated_scripts/`.

O comando `python -m src.main report` terminou com código 0. A suíte local terminou com 39 testes aprovados.

## Arquivos criados ou modificados

Criados:

- `src/fase6_report.py`
- `tests/test_fase6_report.py`
- `results/summary.csv`
- `results/charts/taxa_correcao_sintatica.png`
- `results/charts/analise_estatica.png`
- `results/charts/aprovacao_seguranca.png`
- `results/charts/taxa_remediacao.png`
- `results/charts/tempo_geracao.png`
- `results/charts/consumo_tokens.png`
- `results/fase6/auditoria.json`
- `results/fase6/revalidation/rep02/`, `rep03/` e `rep04/` (`validation.json` e `validation.log` novos)
- `docs/arquitetura/fluxo_experimental.mmd`
- `docs/arquitetura/fluxo_experimental.svg`
- `docs/arquitetura/fluxo_experimental.png`
- `docs/auditoria_fase6.md`

Modificados:

- `src/main.py`, para ativar `report`
- `src/script_validator.py`, com `persist_dir` para a releitura não gravar por cima do log original
- `tests/test_authorization.py` e `tests/test_script_validator.py`
- `requirements.txt`, com `matplotlib` para os PNG
- `docs/resultados_tcc.md`, `docs/execucao.md`, `docs/limitacoes.md`, `docs/metodologia.md`
- `docs/arquitetura/descricao_arquitetura.md`
- `scenarios/README.md`
- `README.md`

Não modificados: `results/experiments.json`, `results/experiments.csv`, `generated_scripts/**/remediation.sh`, `generated_scripts/**/validation.json`, `generated_scripts/**/validation.log` e as evidências SSM.

## Resultados confirmados

| Afirmação | Conferência |
| --- | --- |
| Quatro chamadas à API, uma com HTTP 429 | ledger, `rep01.json` e `fase3_generate_status.json` concordam em 3370 ms e `credit_balance_exhausted` |
| Três scripts, hashes iguais aos metadados | SHA-256 de `remediation.sh` igual a `script_hash_sha256` |
| Tokens e latência das repetições 2, 3 e 4 | ledger igual ao `metadata.json`: 6201 ms (585/548), 6834 ms (585/695), 5625 ms (585/651), 0 tokens de raciocínio |
| Três execuções `Success` | `ssm-execute.json` e a linha `execute` do ledger |
| Versão antes e depois | `1.21.4-1ubuntu4` → `1.21.4-1ubuntu4.5` no ledger, em `verify_before_execute.json`, em `verify_after_execute.json` e no stdout `Unpacking wget (1.21.4-1ubuntu4.5) over (1.21.4-1ubuntu4)` |
| Critério oficial de `noble` | Ubuntu CVE Tracker e OSV da USN-6852-1: corrigida a partir de `1.21.4-1ubuntu4.1` |
| Releitura com o validador atual | os três scripts passam de novo; o `passed` coincide com o `validation.json` preservado |
| Restauração antes das repetições 3 e 4 | `ssm-prepare-rep03.json` e `ssm-prepare-rep04.json`, status `Success`, versão instalada `1.21.4-1ubuntu4` |
| Limpeza | `cleanup-fase3.json`, 14 itens com `ok: true` |

`results/experiments.csv` tem 11 linhas, as mesmas 11 do JSON, com a mesma repetição, latência e `version_after`.

## Divergências

- `experiments.json` tem a chave extra `_allowlist`, às vezes duplicada no mesmo objeto. Não faz parte do esquema de métricas. Os cálculos ignoram essa chave. O CSV acrescenta ` // pragma: allowlist secret` ao campo `notes`.
- `results/CVE-2024-38428/rep02.json`, `rep03.json` e `rep04.json` guardam só o último evento. A latência não está nesses três arquivos; está na linha `generate_only` do ledger.
- A repetição 1 tem `validate` e `execute` recusados em `fase3_generate_status.json`, com `ssm_command_sent: false`. O ledger só tem a linha `generate_error`.
- A primeira validação da repetição 2 está no ledger como `validation_passed: false`, e o motivo está em `fase3_rep02_status.json`. O `validation.json` dessa passagem foi sobrescrito pela segunda, aprovada.
- A repetição 2 tem dois comandos de verificação posteriores à execução (`verify_after_execute.json` e `verify_independent.json`). As versões coincidem; os identificadores SSM não.
- A página HTML da USN-6852-1 não foi obtida (HTTP 503 e, depois, tempo esgotado). O tracker e o OSV concordam. A USN-8543-2, ao recapitular avisos, diz que a CVE-2024-38428 só afetou o Ubuntu 14.04. Essa frase não foi usada para mudar o critério nem os resultados.
- A figura de topologia continua com o rótulo de região redigido na fonte Mermaid. A região aplicada foi `us-east-2`.
- `docs/resultados_tcc.md`, antes desta consolidação, repetia os parágrafos das repetições 3 e 4. O texto foi reescrito a partir das evidências.
- `scenarios/README.md` ainda descrevia o bloqueio da SCP como estado atual. A seção foi atualizada.

## Evidências ausentes

- JSON próprio das tentativas de provisionamento 1, 2 e 3. Só a narrativa de `evidence/STATUS.md` as menciona.
- `validation.json` e `validation.log` da primeira passagem da repetição 2.
- Horário dentro de `cleanup-fase3.json`.
- Página HTML da USN-6852-1 nesta consulta.
- `prepare.sh` antes da repetição 2. Não era necessário: a instância já estava vulnerável desde a Fase 2, e `verify_before_execute.json` confirma isso.
- Experimentos das outras nove CVEs.

## Limitações metodológicas

Uma CVE, um modelo nas gerações que produziram script, três execuções a partir do mesmo estado vulnerável. A chamada HTTP 429 entra na latência e no denominador de chamadas; não entra na taxa de sintaxe, porque não houve script. A taxa 3/4 de aprovação de segurança usa os quatro eventos do ledger. A taxa 3/3 usa só o laudo final preservado. As duas estão no `summary.csv` e não se substituem.

A releitura da Fase 6 usa o validador já corrigido. Ela não reproduz a reprovação antiga. A redução de esforço manual não foi medida.

## Pendências para a pré-banca

- Ler a página HTML da USN-6852-1 quando o site responder e anexar a citação literal da versão de `noble`.
- Decidir, no texto do TCC, como apresentar a frase da USN-8543-2 que restringe a CVE-2024-38428 ao Ubuntu 14.04, sem apagar o critério do tracker.
- Não tratar 3/3 como taxa única de segurança: a primeira passagem da repetição 2 reprovou.
- Se o trabalho precisar de mais de um pacote, aprovar outra ficha e provisionar de novo. Esta consolidação não abre esse experimento.
- `docs/ambiente.md` ainda descreve a Fase 1 como validação local, anterior ao `apply`. Não é o estado do experimento; o estado está em `docs/resultados_tcc.md`.
