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

**Sem chave OpenAI:** `generate` encerra com erro amigável e não inventa script. No Cloud Agent, adicione `OPENAI_API_KEY` (e opcionalmente `OPENAI_MODEL`) em Environment secrets no dashboard do Cursor — nunca cole o valor no chat — e inicie um novo agente. `check`, `validate`, `verify` e `pytest` não dependem da chave.

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

**Regra:** scripts gerados por IA **não** são enviados ao SSM sem `--authorize AUTORIZO_EXECUCAO_SCRIPT_IA`. Scripts que falham a validação, ou que nem chegaram a ser gravados, são rejeitados por `execute` antes de qualquer chamada ao SSM.

## Tentativa de 12 de novembro de 2026

`OPENAI_API_KEY` estava no ambiente e `OPENAI_MODEL=gpt-4.1`. A EC2 `i-04da3315297ec6c04` em `us-east-2` estava `running`, SSM Online.

| Comando | Código | Resultado |
| --- | --- | --- |
| `generate --cve CVE-2024-38428` | 1 | HTTP 429 `insufficient_quota` / `credit_balance_exhausted`. Latência 3370 ms. Sem script. |
| `validate --cve CVE-2024-38428` | 1 | `remediation.sh` ausente em `rep01`. |
| `execute ... --authorize AUTORIZO_EXECUCAO_SCRIPT_IA` | 1 | Recusado localmente. Nenhum comando SSM. |

A conta OpenAI precisa de créditos antes de uma nova geração. A instância de laboratório não foi modificada nessa tentativa.

## Tentativa de 12 de novembro de 2026, 08:18 (horário de Brasília)

`OPENAI_MODEL=gpt-6-luna`, com `reasoning_effort=none` e `temperature` 0.2. A EC2 `i-04da3315297ec6c04` estava `running`, SSM Online. <!-- pragma: allowlist secret -->

| Comando | Código | Resultado |
| --- | --- | --- |
| `generate --cve CVE-2024-38428` | 0 | `rep02`, 6201 ms, 1133 tokens, 0 de raciocínio |
| `validate` na primeira passagem | 1 | checklist tratou `$PACKAGE` e `||` como pacotes fora do escopo |
| `validate` após o ajuste do checklist | 0 | `bash -n`, ShellCheck e Nível 3 aprovados |
| `execute` com a frase de autorização | 0 | SSM Success. Antes `1.21.4-1ubuntu4`; depois `1.21.4-1ubuntu4.5` |
| `verify` | 0 | `corrigido_por_versao`, independente do texto do modelo |

## Preparação documentada da CVE aprovada

A CVE aprovada para o primeiro experimento é **CVE-2024-38428 (`wget`)**. Scripts em `scenarios/CVE-2024-38428/` (`prepare.sh`, `verify_before.sh`, `verify_after.sh`) destinam-se à EC2 privada via SSM.

Versões oficiais (USN-6852-1): vulnerável `1.21.4-1ubuntu4`; corrigida `1.21.4-1ubuntu4.1`.

## Repetições 3 e 4 — 12 de novembro de 2026, 08:46 (horário de Brasília)

Antes de cada geração, `prepare.sh --apply` reinstalou `wget` `1.21.4-1ubuntu4` e `verify` confirmou `vulneravel_por_versao`.

| Repetição | Geração | Validação | Execução | Antes | Depois |
| --- | --- | --- | --- | --- | --- |
| 3 | 6834 ms, 585/695 tokens | aprovada | SSM Success | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.5` |
| 4 | 5625 ms, 585/651 tokens | aprovada | SSM Success | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.5` |

As duas tiveram 0 tokens de raciocínio. `remediation_success` é verdadeiro nas duas.

## Estado da infraestrutura

A pilha `fase-2-wget` em `us-east-2` foi destruída em 12 de novembro de 2026, por volta das 08:49 (horário de Brasília), depois da frase `AUTORIZO_DESTRUIR_RECURSOS`. Saíram a instância `i-04da3315297ec6c04`, o NAT `nat-055a7c92e17eb05b8`, o EIP, o Internet Gateway, as subnets, as route tables, o security group, a VPC `vpc-0d85cf02d23b63442` e a role `tcc-lab-ssm-*`. A consulta posterior não encontrou VPC nem instância com a tag `Project=tcc-gpt-linux`.

O binário do Terraform não estava no PATH desta máquina e o `terraform.tfstate` local, que não é versionado, também não estava. Por isso o `cleanup` da CLI não enxergava a pilha. A destruição usou os recursos já etiquetados `ExperimentId=fase-2-wget`. Registro: `scenarios/CVE-2024-38428/evidence/cleanup-fase3.json`.

## Relatórios

```bash
python -m src.main report
```

O comando lê `results/experiments.json`, os `validation.json` preservados e as evidências SSM. Grava `results/summary.csv`, `results/experiments.csv`, os gráficos `taxa_correcao_sintatica.png`, `analise_estatica.png`, `aprovacao_seguranca.png`, `taxa_remediacao.png`, `tempo_geracao.png`, `consumo_tokens.png` e `cost.png` em `results/charts/`, as tabelas `infrastructure_attempts.csv`, `api_calls.csv` e `experimental_runs.csv`, e o laudo em `results/revalidation.json` e `results/fase6/revalidation/`. Não chama a AWS, não chama a OpenAI e não reescreve o ledger nem os scripts gerados. Código 0 quando os números conferem; código 1 quando há divergência de versão, token, hash ou status.

## Reexecução já realizada

Em 12 de novembro de 2026, à tarde, os três scripts originais do `wget` foram executados de novo, sem nova chamada à API. Cada script usou uma EC2 nova de uma AMI privada. O registro está em `docs/reexecucao_resultado.md`.
