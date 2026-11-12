# Metodologia

## Delimitação

O trabalho analisa o uso de um único modelo GPT, acessado pela API da OpenAI, para gerar scripts Bash de remediação de vulnerabilidades em Linux. A avaliação prevista considera correção sintática, qualidade estática, adequação técnica, segurança das operações, execução, eficácia da remediação, consistência entre gerações, tempo de geração, tokens e custo estimado.

Não há comparação entre modelos. Não há comparação experimental entre remediação manual e remediação assistida por IA. A possível redução de esforço manual será discutida apenas como benefício potencial. Ela não foi medida e nenhum percentual de redução será apresentado.

## Situação da Fase 1

A Fase 1 constrói o ambiente controlado em que essa avaliação poderá ocorrer. O ambiente é uma VPC exclusiva, com instância Ubuntu descartável, sem IP público e acessível pelo Systems Manager. A definição está em Terraform e foi validada localmente.

Nesta fase não foi selecionada nenhuma CVE. Não foi preparado um estado vulnerável, não foi chamado um modelo generativo e não foi produzido script de remediação. Também não há resultado de execução. Qualquer classificação de sucesso, falha, bloqueio ou caso inconclusivo depende de comprovação independente, que ainda não ocorreu.

## Critérios que permanecem para as fases seguintes

Um script só poderá ser considerado eficaz se a versão do pacote, o status da CVE e o funcionamento do pacote forem verificados com dados independentes da resposta do modelo. A execução com código de saída zero, a ausência de alertas do ShellCheck ou uma afirmação do próprio modelo não bastam para declarar sucesso.

As gerações futuras devem usar o mesmo modelo, o mesmo template e o mesmo estado vulnerável inicial. Todos os resultados, inclusive falhas, serão registrados. Esta fase não antecipa esses registros.

## Reprodutibilidade do que já existe

A pilha usa variáveis com padrão explícito, AMI oficial da Canonical e estado local do Terraform. Os comandos de criação e destruição exigem frases distintas de autorização. O exemplo versionado mantém NAT, endpoints e instâncias desligados, de modo que a reprodução da Fase 1 não cria recurso pago.
