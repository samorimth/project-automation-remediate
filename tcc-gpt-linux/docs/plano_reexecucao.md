# Plano da reexecução controlada

Este plano não foi executado. Nenhum recurso AWS foi criado nesta etapa e os três scripts originais não rodaram de novo. A reexecução só começa com as frases `AUTORIZO_RECURSOS_PAGOS` e `AUTORIZO_EXECUCAO_SCRIPT_IA`. A destruição posterior pede `AUTORIZO_DESTRUIR_RECURSOS`.

## O que seria reexecutado

Os arquivos originais, sem edição:

- `generated_scripts/CVE-2024-38428/rep02/remediation.sh`
- `generated_scripts/CVE-2024-38428/rep03/remediation.sh`
- `generated_scripts/CVE-2024-38428/rep04/remediation.sh`

Não há nova geração na OpenAI. O conjunto histórico permanece em `results/experimental_runs.csv`. O conjunto novo, se existir, terá outro prefixo de identificador e outro diretório de evidências.

## Recursos

| Recurso | Papel | Duração prevista |
| --- | --- | --- |
| VPC, subnets, NAT, security group e role SSM já descritos no Terraform | infraestrutura compartilhada, criada uma vez | a janela inteira |
| Uma instância auxiliar `t3.small` | instalar `wget 1.21.4-1ubuntu4`, conferir o estado vulnerável e gerar a AMI privada | só o tempo de preparo; depois é destruída |
| AMI privada | Ubuntu 24.04, pacote vulnerável, agente SSM, sem credencial | permanece até a limpeza autorizada da imagem |
| Três EC2 `t3.small`, uma por vez | cada uma nasce da mesma AMI e executa um único script | o tempo de uma repetição; em seguida só essa instância é destruída |

`max_simultaneous_instances` fica em 1. O código em `src/fresh_instance.py` recusa reutilizar um `instance_id` e recusa `prepare.sh --apply` como forma de restaurar uma instância já usada. Se o estado inicial não for `1.21.4-1ubuntu4`, o script não roda e a repetição fica INCONCLUSIVO.

A AMI histórica `ami-096d6538c463eb1db` é pública da Canonical. Ela não serve como AMI de referência deste plano. O ID da AMI privada só será conhecido depois do preparo autorizado.

## Procedimento

1. Conferir a região `us-east-2` e a frase de autorização de recursos pagos.
2. Subir a infraestrutura compartilhada. Não criar as três instâncias de repetição ainda.
3. Subir a instância auxiliar a partir da AMI Ubuntu 24.04 da Canonical.
4. Instalar o `.deb` vulnerável cujo SHA-256 histórico é `1d078bf2a22c2c6da84788818ebf055a10f5f6b5ea629f1dd0dd11660b51def6`.
5. Confirmar, por `dpkg-query` e `dpkg --compare-versions`, que a versão é `1.21.4-1ubuntu4` e que ela é menor que `1.21.4-1ubuntu4.1`.
6. Confirmar o agente SSM. Retirar credenciais e dados que não pertençam à imagem.
7. Criar a AMI privada e registrar ID, data, CVE, pacote, versões e hash.
8. Destruir a instância auxiliar.
9. Para cada script, criar uma EC2 nova dessa AMI, esperar o SSM, gravar `instance_id` e `ami_id`, repetir a verificação inicial e salvar `before.json`.
10. Executar só o script daquela repetição. Gravar stdout, stderr, código de saída e duração.
11. Verificar de novo com `dpkg-query` e `dpkg --compare-versions`. Rodar um teste funcional do `wget` contra um arquivo local, sem explorar a CVE. Scanner entra só se estiver disponível; a ausência de alerta, sozinha, não comprova a correção.
12. Copiar `after.json` e `evidence.md` para fora da instância e conferir os hashes.
13. Destruir somente essa EC2 e registrar a limpeza.
14. Ao final, destruir a AMI e a infraestrutura compartilhada somente com autorização explícita de destruição.

## Custo estimado

Os preços abaixo são os já escritos em `docs/ambiente.md`, consultados em 11 de novembro de 2026 para a região anterior, não uma cotação nova de `us-east-2` e não uma fatura:

- `t3.small`: US$ 0,0208 por hora
- NAT Gateway: US$ 0,045 por hora mais US$ 0,045 por GB
- endereço público associado: US$ 0,005 por hora
- volume gp3: US$ 0,08 por GiB-mês

Uma janela de cerca de quatro horas, com o NAT ligado, uma instância auxiliar e três instâncias sequenciais, fica na mesma ordem já estimada nesse documento: cerca de US$ 0,30 antes de imposto e do tráfego de pacotes, se tudo for destruído ao terminar. O NAT deixado ligado a noite inteira custa cerca de US$ 1,08 por dia, sem contar o tráfego. A conferência de preço vigente em `us-east-2` permanece pendente até a autorização.

O custo das chamadas de geração já feitas, com a tabela pública de US$ 0,10 e US$ 0,50 por milhão de tokens, é cerca de US$ 0,001 no total das três respostas. A reexecução não gera custo novo de API porque não chama a OpenAI.

## Critérios de aceite da reexecução

- Três `instance_id` diferentes e um único `ami_id` privado.
- Estado vulnerável comprovado em cada instância antes do script.
- Cada instância executa um único script original.
- `after.json` e o teste funcional ficam fora da instância.
- As instâncias temporárias são destruídas.
- Os resultados novos não são somados aos históricos sem identificação do conjunto.
