# Resultados

Não há resultado experimental positivo nesta fase.

A **CVE-2024-38428 (`wget`)** foi **aprovada** e, em seguida, houve autorização humana para recursos pagos. As tentativas de provisionamento foram classificadas como **BLOQUEADO**: primeiro por ausência de credenciais AWS no Cloud Agent; nas tentativas 3–4, com credenciais e STS OK, por **deny de SCP** `p-xikt6vmn` em EC2 para o usuário IAM `cursor_agent` (tentativa 4: probe em `AWS_DEFAULT_REGION` (Environment), apply não iniciado). Evidência honesta em `scenarios/CVE-2024-38428/evidence/` (`STATUS.md`, `before.json` com `classification=BLOQUEADO`). Nenhum script de remediação foi gerado por GPT. Nenhuma instância foi criada. Nenhum Instance ID, AMI ou versão `wget` observada foi inventado.

Os arquivos previstos para os resultados quantitativos ainda não podem ser preenchidos:

- `results/experiments.csv`
- `results/experiments.json`
- `results/summary.csv`
- os gráficos de sintaxe, remediação, segurança, tempo, tokens e custo

Produzir esses arquivos com valores fictícios comprometeria o trabalho. Eles serão gerados somente quando houver execuções reais, incluindo falhas, bloqueios, casos inconclusivos e gerações não executadas.

A Fase 1 deixa registrada a infraestrutura que permitirá obter esses dados e o critério de que a eficácia depende de verificação independente da resposta do modelo. A redução de esforço manual continua fora do conjunto de resultados, porque não foi medida.
