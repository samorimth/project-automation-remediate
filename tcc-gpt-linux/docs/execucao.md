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

## Preparação documentada da CVE aprovada (ainda offline)

A CVE aprovada para o primeiro experimento é **CVE-2024-38428 (`wget`)**. Os rascunhos em `scenarios/CVE-2024-38428/` (`prepare.sh`, `verify_before.sh`, `verify_after.sh`) são para uso futuro na EC2 privada via SSM. Em uma máquina Ubuntu 24.04 de laboratório:

```bash
bash scenarios/CVE-2024-38428/prepare.sh --check
# somente após autorização de recursos pagos e EC2 privada:
# sudo bash scenarios/CVE-2024-38428/prepare.sh --apply
# bash scenarios/CVE-2024-38428/verify_before.sh
```

Versões oficiais (USN-6852-1 / OSV / Ubuntu CVE Tracker): vulnerável `1.21.4-1ubuntu4`; corrigida `1.21.4-1ubuntu4.1`. Nenhum desses scripts foi executado contra EC2 nesta entrega. Provar a vulnerabilidade em AWS ainda exige ligar NAT/execução e a frase `AUTORIZO_RECURSOS_PAGOS`.

## Comandos das fases seguintes

`generate`, `validate`, `execute`, `verify` e `report` respondem que a fase ainda não está ativa e terminam com código 2. A CVE já foi escolhida para documentação/preparação, mas nenhum script de remediação foi gerado por GPT e nenhuma execução experimental ocorreu.
