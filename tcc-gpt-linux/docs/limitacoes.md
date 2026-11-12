# Limitações

## Limitações desta fase

A infraestrutura foi validada como código. Ela não foi aplicada na conta AWS. Por isso, ainda não há evidência de que o Systems Manager registrou uma instância, de que a AMI Ubuntu foi resolvida na conta ou de que o user data iniciou o agente. Essas confirmações dependem de um `apply` autorizado e de uma verificação posterior.

A CVE-2024-38428 foi aprovada e a autorização de recursos pagos foi recebida, mas a execução permanece **BLOQUEADA**: após as chaves AWS entrarem no Environment, o usuário IAM `cursor_agent` ainda sofre deny explícito de SCP (`p-xikt6vmn`) em APIs EC2 — inclusive com managed policies EC2/VPC/SSM/IAM anexadas (Allow IAM não supera Deny SCP). O estado vulnerável **ainda não** foi materializado em EC2, nenhum script de remediação foi gerado por GPT e não há resultado experimental positivo. `prompts` e `generated_scripts` continuam sem dados de modelo. Gráficos de eficácia não foram produzidos.

## Limitações do desenho

A instância de laboratório depende de um NAT Gateway para o Systems Manager e para a atualização de pacotes. Esse é o principal custo horário. Os VPC endpoints do Systems Manager não substituem essa saída, porque não alcançam os repositórios Ubuntu.

A pilha usa uma zona de disponibilidade e, no padrão, uma instância. O limite de três instâncias acompanha a meta de três gerações por CVE, ainda não executadas. A região padrão é a configurada em `AWS_DEFAULT_REGION` no Environment por custo. A distância entre o operador e a Virgínia do Norte não altera o procedimento, que será uma execução remota pelo Systems Manager, mas a escolha da região precisa permanecer registrada.

O security group não oferece SSH. A operação da instância fica restrita ao Systems Manager. Isso é intencional e impede o uso da instância se o agente ou a role não funcionarem.

## O que não foi medido

A redução de esforço manual não foi medida. Não há tempo de correção humana, não há comparação com um procedimento manual e não há percentual de economia. Qualquer menção futura a esse benefício deve permanecer qualitativa, salvo um desenho experimental novo, autorizado à parte.

Também não foram medidos tokens, latência de modelo ou custo de API. A integração com a OpenAI não faz parte desta fase.
