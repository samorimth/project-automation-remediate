# Resultados

A **CVE-2024-38428 (`wget`)** permanece a CVE aprovada. A Fase 2 provou o estado vulnerável na instância `i-04da3315297ec6c04` (`wget=1.21.4-1ubuntu4`).

Nesta entrega da Fase 3, o pipeline de geração/validação/execução foi implementado. A geração ao vivo via OpenAI só ocorre com `OPENAI_API_KEY` configurada (Environment secrets no dashboard, ou `.env` local). Se o usuário pular a inclusão do secret, `generate` permanece bloqueado; o restante do lab (check, pytest, SSM verify, cleanup autorizado) segue disponível. A execução do script GPT na EC2 exige a frase `AUTORIZO_EXECUCAO_SCRIPT_IA` e ainda não foi autorizada nesta rodada, salvo evidência explícita em `generated_scripts/` / `results/`.

Arquivos quantitativos:

- `results/experiments.csv`
- `results/experiments.json`
- `results/summary.csv` (ainda não gerado)
- gráficos (Fase 6)

Somente dados reais são gravados. Nenhum Instance ID, versão ou métrica de tokens é inventado.
