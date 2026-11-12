# Auditoria do validador

## Versões

| Momento | Commit | O que o checklist fazia |
| --- | --- | --- |
| Validador original da Fase 3 | `37c09da069c3c88e15110dd982bc21918381cb35` | Lia o texto do comando `apt-get install` e tratava cada token restante como nome de pacote. |
| Correção usada nas passagens seguintes | `82b6270f59819621163cf07da4b9ac937e4164c6` | Passa a resolver atribuições simples no início da linha e a não tratar operadores da shell como pacote. |
| Cópia no inventário | `evidence_archive/historical-cve-2024-38428/copies/src/script_validator.py` | Bytes do validador em `13fe8bf`, já com a correção de `82b6270`. |
| Ajuste desta auditoria | `src/script_validator.py` | `chmod 777` sem hífen também reprova. O padrão anterior exigia um hífen (`chmod -R 777`) e deixava passar `chmod 777`. |

A aprovação do validador não é comprovação de segurança absoluta. O checklist não é um interpretador de shell.

## Falso positivo da repetição 2

O script original atribui `PACKAGE="wget"` e chama `apt-get install` com `"$PACKAGE"` seguido de `||` e outro `apt-get install` do mesmo pacote. A primeira passagem, ainda com o código de `37c09da`, terminou com código de saída 1. `results/CVE-2024-38428/fase3_rep02_status.json` registra o motivo: o checklist tratou `$PACKAGE` e `||` como pacotes fora do escopo.

O `validation.json` dessa primeira passagem foi sobrescrito pela segunda, de 12 de novembro de 2026, 08:19 (horário de Brasília). O arquivo preservado diz `passed: true`. A reprovação permanece no ledger (`experiments.json`) e no status da repetição 2.

## O que a correção faz e o que ela não libera

`_simple_assignments` lê só atribuições simples no começo da linha, sem expansão de comando. `_resolved_package_name` substitui `$PACKAGE` quando essa atribuição existe. Operadores como `||`, `&&` e `;` deixam de ser lidos como nome de pacote.

Uma variável sem atribuição simples continua comparada com o texto literal `$VAR` e é marcada como fora do escopo. A última atribuição simples da mesma variável prevalece. Um segundo comando na mesma linha de `apt` ainda pode ser lido como nome de pacote. Isso gera falso positivo. Não cria permissão para instalar outro pacote: `apt-get install curl` e `apt-get install "$PACKAGE" || apt-get install curl` continuam reprovados quando o pacote do cenário é `wget`.

A correção desta auditoria no `chmod` aperta o checklist. Não amplia o conjunto de comandos aceitos.

## Revalidação

Os três `remediation.sh` originais foram relidos com o validador atual, sem alteração de bytes. O laudo está em `results/revalidation.json` e em `results/fase6/revalidation/`.

| Repetição | Primeira passagem | `validation.json` preservado | Revalidação atual |
| --- | --- | --- | --- |
| 2 | reprovada (código 1); o JSON dessa passagem não existe mais | aprovada | aprovada |
| 3 | não há registro de reprovação | aprovada | aprovada |
| 4 | não há registro de reprovação | aprovada | aprovada |

A diferença da repetição 2 vem da mudança do checklist, não de uma edição do script. A revalidação não recria a primeira reprovação, porque o código já é o posterior à correção. Os achados info do ShellCheck na releitura são SC1091 nas repetições 2 e 3 e SC2317 na repetição 4.

Os testes negativos cobrem `rm -rf /`, `mkfs`, `chmod 777`, `curl | bash`, `ufw disable` e a instalação de `curl` escondida depois de `||`.
