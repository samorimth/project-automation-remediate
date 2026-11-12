# Limitações

## Limitações desta fase

A infraestrutura está aplicada em `us-east-2` (NAT + EC2) e o estado vulnerável de `wget` foi provado. A Fase 3 adiciona integração OpenAI e validação, mas:

- `OPENAI_API_KEY` presente no ambiente não basta se a organização OpenAI estiver sem créditos. Em 12 de novembro de 2026, 07:44 (horário de Brasília), `generate` com `gpt-4.1` recebeu HTTP 429 `insufficient_quota` (`credit_balance_exhausted`). Nenhum script foi produzido.
- `validate` e `execute` recusam a repetição quando `remediation.sh` não existe ou não passou na validação. `execute` não envia comando ao SSM nesse caso.
- A execução de um script gerado por IA na EC2 continua exigindo a frase `AUTORIZO_EXECUCAO_SCRIPT_IA` e um script já aprovado.
- Recursos pagos (NAT + EIP + `t3.small`) permanecem faturando até cleanup autorizado.

## Limitações do desenho

A instância depende de NAT Gateway para SSM e apt. O security group não oferece SSH. A região experimental atual é `us-east-2`.

O Nível 2 da validação depende do binário `shellcheck` no PATH do ambiente que executa `validate`.

## O que não foi medido

A redução de esforço manual não foi medida. A chamada de 12 de novembro de 2026 não devolveu tokens: a API recusou antes de gerar o script. Latência registrada: 3370 ms. Custo de API não foi cobrado nessa recusa de cota.
