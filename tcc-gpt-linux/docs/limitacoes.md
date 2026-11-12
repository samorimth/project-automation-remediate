# Limitações

## Limitações desta fase

A infraestrutura foi validada como código e, na tentativa 5 (`us-east-2`), **aplicada** com autorização: VPC/NAT/EC2 criados, SSM Online e AMI Ubuntu resolvida. Continua válido que medições de eficácia (tokens, tempo, remediação por modelo) ainda não foram feitas.

A CVE-2024-38428 foi aprovada e a autorização de recursos pagos foi recebida. Tentativas 3–4 em `AWS_DEFAULT_REGION` (lab anterior)/`sa-east-1` ficaram **BLOQUEADAS** pela SCP `p-xikt6vmn` (deny EC2). Na tentativa 5 (`us-east-2`), o probe EC2 passou, o apply criou a instância e o estado vulnerável de `wget` (`1.21.4-1ubuntu4`) foi **provado** via SSM (`prepare.sh` + `verify_before.sh`). Ainda **não** houve script de remediação gerado por GPT/OpenAI; `prompts` e `generated_scripts` continuam sem dados de modelo; gráficos de eficácia não foram produzidos. Recursos pagos em `us-east-2` permanecem ativos até cleanup autorizado.

## Limitações do desenho

A instância de laboratório depende de um NAT Gateway para o Systems Manager e para a atualização de pacotes. Esse é o principal custo horário. Os VPC endpoints do Systems Manager não substituem essa saída, porque não alcançam os repositórios Ubuntu.

A pilha usa uma zona de disponibilidade e, no padrão, uma instância. O limite de três instâncias acompanha a meta de três gerações por CVE, ainda não executadas. A região experimental atual é `us-east-2` (após SCP negar EC2 em `AWS_DEFAULT_REGION` (lab anterior)/`sa-east-1`). A operação continua remota pelo Systems Manager; a região escolhida precisa permanecer registrada.

O security group não oferece SSH. A operação da instância fica restrita ao Systems Manager. Isso é intencional e impede o uso da instância se o agente ou a role não funcionarem.

## O que não foi medido

A redução de esforço manual não foi medida. Não há tempo de correção humana, não há comparação com um procedimento manual e não há percentual de economia. Qualquer menção futura a esse benefício deve permanecer qualitativa, salvo um desenho experimental novo, autorizado à parte.

Também não foram medidos tokens, latência de modelo ou custo de API. A integração com a OpenAI não faz parte desta fase.
