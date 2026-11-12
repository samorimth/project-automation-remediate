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

## Comandos das fases seguintes

`generate`, `validate`, `execute`, `verify` e `report` respondem que a fase ainda não está ativa e terminam com código 2. Um identificador de CVE passado a esses comandos é ignorado. Nenhuma CVE foi escolhida e nenhum script foi gerado.
