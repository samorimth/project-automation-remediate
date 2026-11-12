# Ambiente experimental

## Escopo desta fase

A Fase 1 define o ambiente em que os experimentos futuros poderão ocorrer. O código descreve uma VPC exclusiva na conta pessoal, separada dos recursos que já existem nela. A validação realizada até aqui é local: `terraform validate`, testes automatizados e o comando `check`. Nenhum `terraform apply` foi executado e, portanto, nenhum recurso desta pilha foi criado na AWS.

## Conta e isolamento

O laboratório usa a mesma conta AWS em que já existe uma instância Windows do CopySpider. Essa instância permanece na rede e na região em que já está. O Terraform não consulta a VPC default, não altera security groups existentes e não recebe o identificador dessa instância. O estado é local e cobre somente os recursos declarados neste diretório.

A região padrão experimental atual é `us-east-2`. Antes, o padrão de custo era `AWS_DEFAULT_REGION` (lab anterior) (o enunciado sugeria `sa-east-1`). A troca para `us-east-2` nesta tentativa (Fase 2 / CVE-2024-38428) visa contornar o deny explícito da SCP `p-xikt6vmn` observado em `AWS_DEFAULT_REGION` (lab anterior) e `sa-east-1`; se a SCP negar EC2 em todas as regiões, o provisionamento permanece BLOQUEADO. A variável `aws_region` aceita `AWS_DEFAULT_REGION` (lab anterior), `us-east-2` e `sa-east-1`. O experimento depende da AMI Ubuntu 24.04 LTS oficial da Canonical na região escolhida.

## Topologia

A VPC `10.42.0.0/16` tem duas subnets na mesma zona de disponibilidade:

- `10.42.0.0/24`, reservada ao NAT Gateway. Nenhuma instância de laboratório é colocada nela, e o atributo de IP público automático fica desligado.
- `10.42.1.0/24`, privada, destinada à EC2 Ubuntu.

O security group da instância não tem regra de entrada. A saída permite DNS para o resolvedor da própria VPC, HTTP e HTTPS. Não há key pair, não há SSH exposto e a instância é criada sem IP público. O acesso previsto, quando a execução for autorizada, é o AWS Systems Manager.

A AMI padrão é a Ubuntu 24.04 LTS mais recente publicada pela Canonical, owner `099720109477`. O SSM Agent já faz parte dessas AMIs. O user data apenas confirma que o serviço está ativo. Ele não instala pacote adicional e não contém credencial. O metadado da instância exige IMDSv2. O volume raiz é gp3, de 20 GiB, criptografado, e é removido junto com a instância.

Enquanto `enable_execution` for falso, a quantidade efetiva de instâncias é zero, mesmo que `instance_count` seja maior. `instance_count` não pode passar de `max_instances`, e `max_instances` fica entre 1 e 3.

## Systems Manager e atualização de pacotes

A role da instância recebe somente a política gerenciada `AmazonSSMManagedInstanceCore`. Não há access key na instância.

Para a instância privada alcançar o Systems Manager e os repositórios Ubuntu, o caminho previsto é um NAT Gateway na subnet reservada. Os VPC endpoints de interface `ssm`, `ssmmessages` e `ec2messages` também estão no código. Eles permitem o registro no Systems Manager sem internet, mas não alcançam os repositórios de pacotes. Por isso, ligar a EC2 exige o NAT Gateway. Os três interruptores nascem desligados:

- `enable_nat_gateway`
- `enable_ssm_vpc_endpoints`
- `enable_execution`

## Custos potenciais

Os valores abaixo são preços públicos de `AWS_DEFAULT_REGION` (lab anterior) consultados em 11 de novembro de 2026. Não são uma fatura. Impostos e o volume de dados podem alterar o total.

- EC2 `t3.small` sob demanda: US$ 0,0208 por hora. Em 24 horas, cerca de US$ 0,50, fora a transferência.
- EBS gp3: US$ 0,08 por GiB-mês, conforme a página de volumes General Purpose da AWS. Vinte GiB ficam em torno de US$ 1,60 se o volume permanecer o mês inteiro.
- NAT Gateway: US$ 0,045 por hora e US$ 0,045 por GB processado. Ocioso, a hora do gateway representa cerca de US$ 1,08 por dia.
- Endereço IPv4 público associado ao NAT: US$ 0,005 por hora, cerca de US$ 0,12 por dia.
- Uma janela de cerca de 4 horas, com NAT e uma `t3.small`, fica na ordem de US$ 0,30 antes de impostos e dos gigabytes processados por uma atualização de pacotes. Esse volume de download não foi medido, porque nenhuma instância foi criada.
- VPC, subnets, route tables, security groups, Internet Gateway e IAM não têm cobrança horária própria.

O NAT é o componente que mais pesa se permanecer ligado fora da janela do experimento. O procedimento previsto é criar os recursos somente durante o experimento e destruí-los em seguida, cada ação com autorização própria.

Snapshots e buckets S3 não fazem parte desta pilha. VPC endpoints de interface permanecem desligados. Cada endpoint é cobrado por hora e por zona de disponibilidade; três endpoints tendem a custar mais do que um NAT mantido por poucas horas e, ainda assim, não substituem o NAT na atualização de pacotes.

As fontes usadas para estas estimativas foram a página de preço do Amazon VPC, a página de volumes General Purpose do Amazon EBS e o preço sob demanda publicado para a instância `t3.small` em `AWS_DEFAULT_REGION` (lab anterior).

## Pré-requisitos

No computador de orquestração: Python 3.11 ou superior, Terraform 1.6 ou superior e, apenas antes de um plano contra a conta, AWS CLI com credencial de operador. A chave da OpenAI, quando existir nas fases seguintes, fica no `.env` local. Esse arquivo está no `.gitignore` e não é enviado à EC2.
