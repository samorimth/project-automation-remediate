# Descrição da arquitetura

O diagrama [arquitetura.svg](arquitetura.svg) representa somente o que a Fase 1 implementa. Ele separa o ambiente local de orquestração e a conta AWS isolada.

No ambiente local estão o Cursor, a CLI Python e o Terraform. A CLI verifica a configuração, prepara o plano e recusa criação ou destruição sem frase de autorização. O Terraform descreve a pilha. Nesta fase ele foi inicializado e validado localmente. Não foi aplicado.

Na AWS, o diagrama mostra uma VPC exclusiva em `us-east-1`, com subnet pública reservada ao NAT e subnet privada para a instância. A EC2 Ubuntu não tem IP público. O volume gp3 e a role do Systems Manager estão ligados a essa instância. A role usa apenas a política necessária para o agente se registrar. O security group sem entrada não aparece como um bloco separado para manter a figura legível em página A4; ele está definido no código e descrito em [ambiente.md](../ambiente.md).

O fluxo implementado é local: a pessoa opera o Cursor e a CLI, e a CLI chama o Terraform, que declara a VPC. Não há fluxo de CVE, modelo generativo ou script, porque esses componentes ainda não existem no repositório.

Ficam de fora da figura, por ainda não estarem implementados:

- a API da OpenAI e o modelo GPT;
- o template de geração de script;
- a validação sintática, estática e de segurança;
- a execução remota pelo Systems Manager Run Command;
- a verificação independente da remediação;
- as evidências e os relatórios quantitativos.

O modelo generativo não aparece como responsável por validar a própria correção. Essa validação, quando for construída, usará a versão do pacote e o status oficial da CVE, em separado da resposta do modelo.

A instância Windows do CopySpider não integra o diagrama. Ela permanece fora desta VPC e desta pilha.

Os arquivos `arquitetura.mmd`, `arquitetura.svg` e `arquitetura.png` foram gerados a partir da mesma fonte Mermaid, com fundo branco. O PNG e o SVG são figuras da arquitetura já descrita no código, não de uma execução realizada na conta.
