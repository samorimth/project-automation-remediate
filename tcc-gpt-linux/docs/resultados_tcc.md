# Resultados

A **CVE-2024-38428 (`wget`)** permanece a CVE aprovada. A Fase 2 provou o estado vulnerável na instância `i-04da3315297ec6c04` (`wget=1.21.4-1ubuntu4`).

Nesta entrega da Fase 3, o pipeline de geração/validação/execução está implementado. Em 12 de novembro de 2026, 07:44 (horário de Brasília), com `OPENAI_API_KEY` presente e modelo `gpt-4.1`, `generate --cve CVE-2024-38428` falhou: a API respondeu HTTP 429 `insufficient_quota` (`credit_balance_exhausted`). Não houve `remediation.sh`. `validate` encerrou com código 1 (`remediation.sh ausente`). `execute` encerrou com código 1 e não enviou comando ao SSM. A instância `i-04da3315297ec6c04` estava `running` com SSM Online e não foi alterada nesta tentativa. Evidência: `generated_scripts/CVE-2024-38428/rep01/` e `results/CVE-2024-38428/`.

Arquivos quantitativos:

- `results/experiments.csv`
- `results/experiments.json`
- `results/summary.csv` (ainda não gerado)
- gráficos (Fase 6)

Somente dados reais são gravados. Nenhum Instance ID, versão ou métrica de tokens é inventado.
