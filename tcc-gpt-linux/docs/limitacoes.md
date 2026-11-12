# Limitações

## Limitações desta fase

A pilha de `us-east-2` foi destruída depois das repetições. O estado vulnerável de `wget` e as três remediações ficam registrados nas evidências. A Fase 6 apenas consolida esses arquivos. Limitações que permanecem:

- `OPENAI_API_KEY` presente no ambiente não basta se a organização OpenAI estiver sem créditos. Em 12 de novembro de 2026, 07:44 (horário de Brasília), `generate` com `gpt-4.1` recebeu HTTP 429 `insufficient_quota`. Com créditos e `gpt-6-luna`, a repetição 2 de CVE-2024-38428 gerou, validou e corrigiu o `wget`. <!-- pragma: allowlist secret -->
- `validate` e `execute` recusam a repetição quando `remediation.sh` não existe ou não passou na validação. `execute` não envia comando ao SSM nesse caso.
- A execução de um script gerado por IA na EC2 continua exigindo a frase `AUTORIZO_EXECUCAO_SCRIPT_IA` e um script já aprovado.
- A pilha paga de `us-east-2` foi destruída em 12 de novembro de 2026, por volta das 08:49 (horário de Brasília). Uma nova repetição exige provisionar de novo.

## Limitações do desenho

A instância depende de NAT Gateway para SSM e apt. O security group não oferece SSH. A região experimental atual é `us-east-2`.

O Nível 2 da validação depende do binário `shellcheck` no PATH do ambiente que executa `validate`.

## O que não foi medido

A redução de esforço manual não foi medida. A chamada das 07:44 (horário de Brasília) não devolveu tokens: a API recusou antes de gerar o script. A repetição 2, às 08:18, registrou 585 tokens de entrada, 548 de saída e 0 de raciocínio, com latência de 6201 ms. O preço público do `gpt-6-luna` é US$ 0,10 por milhão de tokens de entrada e US$ 0,50 por milhão de saída; esta geração fica abaixo de US$ 0,01. <!-- pragma: allowlist secret -->

As três execuções históricas do `wget` compartilharam a instância `i-04da3315297ec6c04`. A reexecução usou a AMI privada `ami-03629c5c47c71759b`, depois removida. No `less`, os três scripts passaram na validação estática e falharam na execução com código 141, sem alterar a versão `590-2ubuntu2`. A aprovação estática não comprova que o script atualiza o pacote. As páginas HTML da USN-6852-1 e da USN-6756-1 devolveram HTTP 503. O modelo solicitado e o modelo devolvido não estão em campos separados. As taxas do `wget` não se aplicam ao `less`. A VPC e o NAT das duas pilhas foram destruídos em 12 de novembro de 2026.
