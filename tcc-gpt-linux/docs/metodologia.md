# Metodologia

## Delimitação

O trabalho analisa o uso de um único modelo GPT, acessado pela API da OpenAI, para gerar scripts Bash de remediação de vulnerabilidades em Linux. A avaliação prevista considera correção sintática, qualidade estática, adequação técnica, segurança das operações, execução, eficácia da remediação, consistência entre gerações, tempo de geração, tokens e custo estimado.

Não há comparação entre modelos. Não há comparação experimental entre remediação manual e remediação assistida por IA. A possível redução de esforço manual será discutida apenas como benefício potencial. Ela não foi medida e nenhum percentual de redução será apresentado.

## Situação da Fase 1 e da Fase 2 (aprovação CVE)

A Fase 1 constrói o ambiente controlado em que essa avaliação poderá ocorrer. O ambiente é uma VPC exclusiva, com instância Ubuntu descartável, sem IP público e acessível pelo Systems Manager. A definição está em Terraform e foi validada localmente.

Na Fase 2, a **CVE-2024-38428 (`wget`)** foi **aprovada** como primeiro experimento. As demais fichas em `scenarios/` permanecem alternativas. Foram versionados a ficha completa e scripts Bash de preparação/verificação (`prepare.sh`, `verify_before.sh`, `verify_after.sh`) para SSM. A autorização de recursos pagos foi recebida e, na tentativa 3, as credenciais AWS já estavam no run (STS OK). O `terraform apply` ficou **BLOQUEADO** por SCP que nega EC2 ao IAM `cursor_agent`: **não** houve EC2 criada, **não** houve chamada a modelo generativo e **não** há prova experimental do estado vulnerável. Ver `scenarios/CVE-2024-38428/evidence/`.

## Critérios que permanecem para as fases seguintes

Um script só poderá ser considerado eficaz se a versão do pacote, o status da CVE e o funcionamento do pacote forem verificados com dados independentes da resposta do modelo. A execução com código de saída zero, a ausência de alertas do ShellCheck ou uma afirmação do próprio modelo não bastam para declarar sucesso.

As gerações futuras devem usar o mesmo modelo, o mesmo template e o mesmo estado vulnerável inicial. Todos os resultados, inclusive falhas, serão registrados. Esta fase não antecipa esses registros.

## Reprodutibilidade do que já existe

A pilha usa variáveis com padrão explícito, AMI oficial da Canonical e estado local do Terraform. Os comandos de criação e destruição exigem frases distintas de autorização. O exemplo versionado mantém NAT, endpoints e instâncias desligados, de modo que a reprodução da Fase 1 não cria recurso pago.
