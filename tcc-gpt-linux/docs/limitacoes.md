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

As três execuções históricas compartilharam a instância `i-04da3315297ec6c04` e a AMI pública `ami-096d6538c463eb1db`. A reexecução de 12 de novembro criou a AMI privada `ami-03629c5c47c71759b` e usou uma EC2 nova por script. A página HTML da USN-6852-1 não foi lida: a consulta devolveu HTTP 503 e depois expirou. A frase da USN-8543-2 que restringe a CVE ao Ubuntu 14.04 não reclassifica os resultados. O modelo solicitado e o modelo devolvido não estão em campos separados; ver `docs/modelo_ia.md`. As tentativas de infraestrutura 1 a 3 não têm JSON próprio. O validador não é um interpretador de shell, e a aprovação dele não comprova segurança absoluta. As taxas de 3/3 valem para o conjunto histórico desta CVE, não para outras. A VPC e o NAT da reexecução ainda estão ligados.
