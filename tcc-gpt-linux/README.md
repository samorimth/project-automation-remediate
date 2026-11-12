# Laboratório experimental do TCC

Uso da inteligência artificial generativa na geração e validação de scripts para remediação de vulnerabilidades em sistemas operacionais Linux.

Este diretório contém a Fase 1 do laboratório: a definição reproduzível da infraestrutura isolada, a checagem local e o diagrama da arquitetura. A Fase 1 não seleciona CVE, não chama a API da OpenAI, não gera script e não cria recurso na AWS.

## O que esta fase entrega

- VPC exclusiva, subnet privada, security group sem entrada, role do Systems Manager e definição da EC2 Ubuntu.
- NAT Gateway e VPC endpoints presentes no código e desligados por padrão.
- Comandos `check`, `provision` e `cleanup`, com `apply` e `destroy` bloqueados sem frase de autorização.
- Diagrama da arquitetura em Mermaid, SVG e PNG.

## O que esta fase não faz

- Não executa `terraform apply` nem `terraform destroy`.
- Não altera a VPC default nem qualquer instância já existente na conta, como a instância Windows do CopySpider.
- Não mede redução de esforço manual. Essa redução permanece um benefício potencial, sem comprovação quantitativa.

## Pré-requisitos locais

- Python 3.11 ou superior.
- Terraform 1.6 ou superior.
- A AWS CLI só passa a ser necessária quando houver autorização para planejar a conta real.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m src.main check
terraform -chdir=terraform init -input=false
terraform -chdir=terraform validate
pytest
```

## Autorização para recursos pagos

Os padrões deixam `enable_execution`, `enable_nat_gateway` e `enable_ssm_vpc_endpoints` em `false`. Mesmo depois de ligar esses valores em um `terraform.tfvars` local, que não deve ser commitado, os comandos abaixo continuam sem efeito pago até a frase correspondente.

```bash
python -m src.main provision
python -m src.main provision --authorize AUTORIZO_RECURSOS_PAGOS
python -m src.main cleanup
python -m src.main cleanup --authorize AUTORIZO_DESTRUIR_RECURSOS
```

`provision` sem a frase executa `init`, `validate` e `plan`. `cleanup` sem a frase executa `plan -destroy`. Nenhum dos dois cria ou apaga recurso.

A região padrão é `us-east-1`, escolhida pelo custo menor de NAT, EC2 e EBS. A variável `aws_region` aceita também `sa-east-1`. Os custos estimados estão em [docs/ambiente.md](docs/ambiente.md).

## Comandos ainda inativos

`generate`, `validate`, `execute`, `verify` e `report` encerram com código 2 e não produzem script, chamada de API nem recurso. Eles pertencem às fases seguintes.

## Documentação

- [docs/ambiente.md](docs/ambiente.md)
- [docs/metodologia.md](docs/metodologia.md)
- [docs/execucao.md](docs/execucao.md)
- [docs/limitacoes.md](docs/limitacoes.md)
- [docs/resultados_tcc.md](docs/resultados_tcc.md)
- [docs/arquitetura/descricao_arquitetura.md](docs/arquitetura/descricao_arquitetura.md)
