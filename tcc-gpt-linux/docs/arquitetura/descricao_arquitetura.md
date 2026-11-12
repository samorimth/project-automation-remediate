# Descrição da arquitetura

O diagrama [arquitetura.svg](arquitetura.svg) descreve a topologia do laboratório: ambiente local de um lado e a VPC exclusiva do outro. Essa topologia foi aplicada em `us-east-2` na tentativa 5 e destruída depois das repetições da CVE-2024-38428. O rótulo da região na fonte Mermaid está redigido; a região efetivamente usada está em `scenarios/CVE-2024-38428/evidence/before.json`.

No ambiente local estão o Cursor, a CLI Python e o Terraform. A CLI verifica a configuração, prepara o plano e recusa criação ou destruição sem frase de autorização.

Na AWS, o diagrama mostra a VPC `10.42.0.0/16`, a subnet reservada ao NAT e a subnet privada da instância. A EC2 Ubuntu não tem IP público. O volume gp3 e a role do Systems Manager estão ligados a essa instância. A role usa apenas `AmazonSSMManagedInstanceCore`. O security group sem entrada não aparece como um bloco separado para manter a figura legível em página A4; ele está definido no código e descrito em [ambiente.md](../ambiente.md).

O fluxo do experimento, que a figura de topologia não mostra, está em [fluxo_experimental.svg](fluxo_experimental.svg) e [fluxo_experimental.png](fluxo_experimental.png), com a mesma sequência em [fluxo_experimental.mmd](fluxo_experimental.mmd):

1. o cenário e o prompt preenchido;
2. a chamada à API da OpenAI, que pode falhar sem produzir script;
3. `remediation.sh`;
4. a validação em três níveis;
5. a parada sem SSM quando a validação reprova;
6. o SSM Run Command na EC2 privada quando o script foi aprovado e a frase de execução foi dada;
7. a verificação por `dpkg`, independente do texto do modelo;
8. `prepare.sh`, que restaurou o `wget` vulnerável antes das repetições 3 e 4.

O modelo não valida a própria correção. A eficácia usada nos resultados é a comparação de versão do pacote.

A instância Windows do CopySpider não integra o diagrama. Ela permanece fora desta VPC e desta pilha.

Os arquivos `arquitetura.mmd`, `arquitetura.svg` e `arquitetura.png` continuam a figura de topologia já existente. Os arquivos `fluxo_experimental.*` foram acrescentados na Fase 6 porque o fluxo experimental ainda não tinha desenho.
