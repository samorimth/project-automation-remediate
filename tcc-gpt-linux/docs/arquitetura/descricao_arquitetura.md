# Descrição da arquitetura

A figura usada no TCC está em [figura-projeto-tcc.png](figura-projeto-tcc.png). O PDF de origem está em [ProjetoTCC.pdf](ProjetoTCC.pdf).

O desenho mostra o caminho do experimento. O cenário da CVE entrega um prompt padronizado à CLI Python, que oferece `generate`, `validate`, `execute` e `verify`. A CLI envia o prompt à API da OpenAI. A API devolve `remediation.sh`. O validador desenhado na figura aplica `bash -n` e ShellCheck. No código há um terceiro nível, o checklist de segurança e de adequação ao pacote alvo, em `src/script_validator.py`. O rótulo da figura não nomeia esse terceiro nível. Somente o script aprovado segue para o Systems Manager Run Command.

A região desenhada é `us-east-2`. A VPC `10.42.0.0/16` separa a sub-rede pública `10.42.0.0/24`, com Internet Gateway e NAT Gateway, da sub-rede privada `10.42.1.0/24`, com a EC2 Ubuntu 24.04. A instância não tem IP público. A saída dela passa pelo NAT. O Terraform cria e remove a infraestrutura. As evidências saem da instância para o ambiente local, em JSON e CSV.

Fora do desenho, e definidos no Terraform, ficam o security group sem regra de entrada, o volume gp3 criptografado, o IMDSv2 e o papel IAM limitado a `AmazonSSMManagedInstanceCore`. Não há SSH. Esses itens estão descritos em [ambiente.md](../ambiente.md).

A verificação independente da versão usa `dpkg` e não depende do texto devolvido pelo modelo. A comparação de versão é a medida de eficácia usada nos resultados. O modelo não valida a própria correção.

No conjunto histórico, as repetições 3 e 4 restauraram o `wget` vulnerável com `prepare.sh` na mesma EC2. Na reexecução de 12 de novembro de 2026, cada script rodou em uma EC2 nova da AMI privada `ami-03629c5c47c71759b`. A pilha foi destruída depois da coleta.
