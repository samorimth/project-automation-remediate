# Execução

## Validação local já prevista

No diretório `tcc-gpt-linux`:

```bash
python -m src.main check
terraform -chdir=terraform init -input=false
terraform -chdir=terraform validate
pytest
```

`check` confirma o Python, a presença do Terraform, as chaves de `.env.example` e o fato de o exemplo do Terraform manter os recursos pagos desligados. Ele não consulta a AWS.

`terraform validate` confere a sintaxe e a consistência interna da pilha. Ele não cria VPC, NAT, instância ou role.

`pytest` cobre o limite de instâncias e a recusa de `apply` e `destroy` quando a frase de autorização está ausente ou incorreta. Os testes substituem a chamada ao Terraform e não enviam comando à AWS.

## Provisionamento

```bash
python -m src.main provision
```

Esse comando executa `terraform init`, `terraform validate` e `terraform plan`. Ao final, informa que o `apply` não foi executado. O plano pode ler a conta AWS, mas não cria recurso.

A criação só ocorre com a frase exata:

```bash
python -m src.main provision --authorize AUTORIZO_RECURSOS_PAGOS
```

Antes disso, é preciso decidir ligar `enable_nat_gateway` e `enable_execution` em um arquivo `terraform/terraform.tfvars` local. Esse arquivo é ignorado pelo Git. Com os padrões atuais, um `apply` criaria a VPC e a role, sem NAT e sem instância. A EC2 continua condicionada aos dois interruptores e ao NAT, porque a instância privada precisa de saída para o Systems Manager e para os repositórios Ubuntu.

## Limpeza

```bash
python -m src.main cleanup
```

Esse comando informa que o `destroy` não foi executado e, em seguida, mostra `terraform plan -destroy`.

A destruição só ocorre com outra frase, diferente da usada no `apply`:

```bash
python -m src.main cleanup --authorize AUTORIZO_DESTRUIR_RECURSOS
```

Nenhum dos dois comandos foi usado com autorização nesta fase.

## Preparação documentada da CVE aprovada

A CVE aprovada para o primeiro experimento é **CVE-2024-38428 (`wget`)**. Os scripts em `scenarios/CVE-2024-38428/` (`prepare.sh`, `verify_before.sh`, `verify_after.sh`) destinam-se à EC2 privada via SSM.

```bash
bash scenarios/CVE-2024-38428/prepare.sh --check
# somente com EC2 privada provisionada:
# sudo bash scenarios/CVE-2024-38428/prepare.sh --apply
# bash scenarios/CVE-2024-38428/verify_before.sh
```

Versões oficiais (USN-6852-1 / OSV / Ubuntu CVE Tracker): vulnerável `1.21.4-1ubuntu4`; corrigida `1.21.4-1ubuntu4.1`.

## Tentativa de execução autorizada (BLOQUEADO)

Em 2026-11-12 o usuário autorizou recursos pagos (`Sim, autorizo` → `enable_nat_gateway`, `enable_execution`, `AUTORIZO_RECURSOS_PAGOS`).

- Tentativas 1–2: **BLOQUEADO** por ausência de `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` no run.
- Tentativa 3: credenciais presentes; `aws sts get-caller-identity` OK (usuário IAM `cursor_agent`); `terraform.tfvars` local com NAT + execução; `python -m src.main provision --authorize AUTORIZO_RECURSOS_PAGOS` executado. O apply **falhou** com **deny explícito de SCP** (`p-xikt6vmn`) em APIs EC2 (`DescribeAvailabilityZones`, `DescribeImages`, etc.) em `regiao-padrao-lab` e `sa-east-1`. **Nenhum recurso criado** (sem estado Terraform). Classificação: **BLOQUEADO**. Evidência: `scenarios/CVE-2024-38428/evidence/`.

Próximo passo: liberar EC2/VPC/IAM/SSM para `cursor_agent` na Organizations/IAM e repetir o provisionamento. Quando o apply for bem-sucedido, a limpeza exigirá `python -m src.main cleanup --authorize AUTORIZO_DESTRUIR_RECURSOS`.

## Comandos das fases seguintes

`generate`, `validate`, `execute`, `verify` e `report` respondem que a fase ainda não está ativa e terminam com código 2. A CVE já foi escolhida para documentação/preparação, mas nenhum script de remediação foi gerado por GPT e nenhuma execução experimental ocorreu.
