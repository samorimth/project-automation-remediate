# Resultados

A **CVE-2024-38428 (`wget`)** permanece a CVE aprovada. A Fase 2 provou o estado vulnerável na instância `i-04da3315297ec6c04` (`wget=1.21.4-1ubuntu4`).

Nesta entrega da Fase 3, o pipeline de geração/validação/execução está implementado. Sem `OPENAI_API_KEY`, `generate` encerra sem inventar script.

Em 12 de novembro de 2026, 07:44 (horário de Brasília), com modelo `gpt-4.1`, `generate` falhou por HTTP 429 `insufficient_quota`. Não houve script. Evidência em `generated_scripts/CVE-2024-38428/rep01/`.

Em 12 de novembro de 2026, 08:18 (horário de Brasília), com créditos na organização e `OPENAI_MODEL=gpt-6-luna` (`reasoning_effort=none`, `temperature` 0.2), a repetição 2 gerou um script em 6201 ms (585 tokens de entrada, 548 de saída, 0 de raciocínio). A validação passou depois que o checklist passou a reconhecer a variável `PACKAGE="wget"` e o operador `||`. A execução SSM `e574d8bc-9ae6-4e75-bce4-d492636cadf4` na instância `i-04da3315297ec6c04` teve sucesso. A verificação independente registrou `wget` `1.21.4-1ubuntu4` antes e `1.21.4-1ubuntu4.5` depois. `remediation_success` é verdadeiro. Evidência em `generated_scripts/CVE-2024-38428/rep02/` e `results/`. <!-- pragma: allowlist secret -->

Arquivos quantitativos:

- `results/experiments.csv`
- `results/experiments.json`
- `results/summary.csv` (ainda não gerado)
- gráficos (Fase 6)

Somente dados reais são gravados. Nenhum Instance ID, versão ou métrica de tokens é inventado.
