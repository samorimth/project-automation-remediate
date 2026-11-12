# Execução

## Validação local já prevista

No diretório `tcc-gpt-linux`:

```bash
python -m src.main check
terraform -chdir=terraform init -input=false
terraform -chdir=terraform validate
pytest
```

`check` confirma o Python, a presença do Terraform e do `shellcheck`, as chaves de `.env.example` e o fato de o exemplo do Terraform manter os recursos pagos desligados. Ele não consulta a AWS.

`terraform validate` confere a sintaxe e a consistência interna da pilha. Ele não cria VPC, NAT, instância ou role.

`pytest` cobre limites de instâncias, autorização de apply/destroy/execute e os validadores da Fase 3 (com mocks da OpenAI).

## Provisionamento

```bash
python -m src.main provision
```

Esse comando executa `terraform init`, `terraform validate` e `terraform plan`. Ao final, informa que o `apply` não foi executado. O plano pode ler a conta AWS, mas não cria recurso.

A criação só ocorre com a frase exata:

```bash
python -m src.main provision --authorize AUTORIZO_RECURSOS_PAGOS
```

## Limpeza

```bash
python -m src.main cleanup
python -m src.main cleanup --authorize AUTORIZO_DESTRUIR_RECURSOS
```

## Fase 3 — geração, validação e execução controlada

Pré-requisitos: `OPENAI_API_KEY` e `OPENAI_MODEL` no ambiente (ou `.env` local, não versionado); `shellcheck` no PATH; instância EC2 com SSM Online (Fase 2).

```bash
# 1) Gerar UM script para a CVE aprovada
python -m src.main generate --cve CVE-2024-38428

# 2) Validar (bash -n + shellcheck + checklist de segurança)
python -m src.main validate --cve CVE-2024-38428

# 3) Executar na EC2 SOMENTE com frase explícita
python -m src.main execute --cve CVE-2024-38428 \
  --instance-id i-04da3315297ec6c04 \
  --authorize AUTORIZO_EXECUCAO_SCRIPT_IA

# 4) Verificar versão do pacote de forma independente
python -m src.main verify --cve CVE-2024-38428 \
  --instance-id i-04da3315297ec6c04
```

Artefatos de cada repetição ficam em `generated_scripts/CVE-2024-38428/repXX/` (`prompt.txt`, `response.txt`, `remediation.sh`, `metadata.json`, `validation.log`, `validation.json`). Métricas reais (sem preenchimento fictício) em `results/experiments.csv` e `results/experiments.json`.

**Regra:** scripts gerados por IA **não** são enviados ao SSM sem `--authorize AUTORIZO_EXECUCAO_SCRIPT_IA`. Scripts que falham a validação perdem o bit de execução e são rejeitados pelo comando `execute`.

## Preparação documentada da CVE aprovada

A CVE aprovada para o primeiro experimento é **CVE-2024-38428 (`wget`)**. Scripts em `scenarios/CVE-2024-38428/` (`prepare.sh`, `verify_before.sh`, `verify_after.sh`) destinam-se à EC2 privada via SSM.

Versões oficiais (USN-6852-1): vulnerável `1.21.4-1ubuntu4`; corrigida `1.21.4-1ubuntu4.1`.

## Estado da infraestrutura (Fase 2)

Tentativa 5 em `us-east-2`: instância `i-04da3315297ec6c04`, SSM Online, `wget=1.21.4-1ubuntu4` (**vulnerável_por_versão**). Evidência: `scenarios/CVE-2024-38428/evidence/`.

**Custo ativo:** NAT + EIP + `t3.small` em `us-east-2` até:

```bash
python -m src.main cleanup --authorize AUTORIZO_DESTRUIR_RECURSOS
```

## Relatórios

`report` permanece reservado à Fase 6 e encerra com código 2.
