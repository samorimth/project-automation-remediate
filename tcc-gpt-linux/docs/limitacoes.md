# Limitações

## Limitações desta fase

A infraestrutura está aplicada em `us-east-2` (NAT + EC2) e o estado vulnerável de `wget` foi provado. A Fase 3 adiciona integração OpenAI e validação, mas:

- Sem `OPENAI_API_KEY` no ambiente do agente, a geração ao vivo fica bloqueada.
- A execução do script gerado por IA na EC2 exige autorização explícita (`AUTORIZO_EXECUCAO_SCRIPT_IA`) e não ocorre automaticamente.
- Recursos pagos (NAT + EIP + `t3.small`) permanecem faturando até cleanup autorizado.

## Limitações do desenho

A instância depende de NAT Gateway para SSM e apt. O security group não oferece SSH. A região experimental atual é `us-east-2`.

O Nível 2 da validação depende do binário `shellcheck` no PATH do ambiente que executa `validate`.

## O que não foi medido

A redução de esforço manual não foi medida. Tokens, latência e custo de API só passam a constar em `results/` após gerações reais bem-sucedidas.
