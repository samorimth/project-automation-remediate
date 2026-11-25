# Auditoria inicial

Data da auditoria local: 12 de novembro de 2026. Nenhum recurso AWS foi criado nesta etapa e nenhuma chamada nova foi feita à API da OpenAI.

## O que foi preservado

A cópia imutável está em `evidence_archive/historical-cve-2024-38428/`.

- `MANIFEST.json` lista 54 arquivos, o commit `13fe8bf544471b11ea01b87d4cc7f620e04c111f` e o SHA-256 de cada original.
- `copies/` guarda os bytes daquele commit: scripts gerados, respostas da API, logs, `experiments.json`, `experiments.csv`, evidências da Fase 2 e o `src/script_validator.py` da época do inventário.
- Os arquivos da cópia estão com permissão somente leitura.

O teste `test_archived_evidence_still_matches_the_working_tree` recalcula os hashes. Evidências científicas que divergirem do manifesto fazem o teste falhar. O código do validador pode mudar depois do inventário; a cópia arquivada não é atualizada para acompanhar essa mudança.

Não entram no arquivo como originais: `results/summary.csv`, os gráficos e `results/fase6/`, porque são derivados da Fase 6.

## O que os originais registram

| Fato | Fonte |
| --- | --- |
| Versão inicial `wget 1.21.4-1ubuntu4` | `verify_before_execute.json` das repetições 2, 3 e 4 |
| Versão depois da execução `1.21.4-1ubuntu4.5` | `verify_after_execute.json` |
| Mínimo oficial usado pelo laboratório `1.21.4-1ubuntu4.1` | `scenario.json` e a verificação por `dpkg --compare-versions` |
| Três scripts gerados e três execuções SSM `Success` | `generated_scripts/CVE-2024-38428/rep02` a `rep04` e `experiments.json` |
| Uma chamada HTTP 429 sem script | `rep01.json` e `fase3_generate_status.json` |
| Mesma instância `i-04da3315297ec6c04` nas três execuções | `before.json` e os JSON de verificação |
| AMI pública da Canonical `ami-096d6538c463eb1db` | `before.json` |
| `prepare.sh --apply` antes das repetições 3 e 4 | `ssm-prepare-rep03.json` e `ssm-prepare-rep04.json` |
| Pilha destruída, 14 itens com `ok=true` | `evidence/cleanup-fase3.json` |

O identificador da tabela é o da imagem pública usada no experimento histórico. A reexecução posterior usou a AMI privada `ami-03629c5c47c71759b`, destruída depois da coleta.
