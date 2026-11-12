# Cenários CVE — Fase 2 (propostas)

Este diretório registra candidatos a CVE para o primeiro experimento do laboratório. A Fase 2, neste ponto, **apenas propõe** três CVEs reais para **aprovação explícita** do autor do TCC.

## Estado desta entrega

| Item | Situação |
| --- | --- |
| Status de aprovação | **pendente** |
| AMI / EC2 vulnerável preparada | **não** |
| Recurso pago AWS criado | **não** |
| `terraform apply` / `destroy` | **não executados** |
| Chamada à API OpenAI | **não** |
| Script gerado por GPT | **não** |
| Resultado experimental inventado | **não** |

Nenhuma preparação de ambiente vulnerável deve ocorrer antes da aprovação de **uma** CVE dentre as propostas abaixo.

## Critérios usados na seleção

- Documentação oficial da Canonical (Ubuntu CVE Tracker e/ou USN).
- Versões vulnerável e corrigida conhecidas para Ubuntu 24.04 LTS (`noble`), alinhada à AMI padrão da Fase 1.
- Remediação por atualização de pacote (`apt`), sem exploração ativa.
- Verificação independente antes/depois via `dpkg -s`, `apt-cache policy` e comparação com a versão corrigida publicada.
- Pacote instalável (ou reinstalável em versão antiga) em EC2 privada, sem expor serviço à Internet.
- Correção disponível no repositório público (sem depender de Ubuntu Pro / ESM).

Fontes consultadas: [Ubuntu CVE Tracker](https://ubuntu.com/security/), [Ubuntu Security Notices](https://ubuntu.com/security/notices), [Ubuntu OSV / USN JSON](https://osv.dev/) e, de forma complementar, NVD/CVE.org. Versões vulneráveis listadas abaixo são as publicadas no OSV da Canonical para `Ubuntu:24.04:LTS`; a versão de preparação sugerida é a última vulnerável registrada para `noble`.

## Candidatos

| CVE | Pacote | Ubuntu | Versão vulnerável (ex.) | Versão corrigida | USN | Detalhe |
| --- | --- | --- | --- | --- | --- | --- |
| [CVE-2025-1372](CVE-2025-1372/scenario.md) | `elfutils` | 24.04 LTS (noble) | `0.190-1.1build4.1` | `0.190-1.1ubuntu0.1` | [USN-7369-1](https://ubuntu.com/security/notices/USN-7369-1) | **Recomendada** como primeiro caso |
| [CVE-2025-0840](CVE-2025-0840/scenario.md) | `binutils` | 24.04 LTS (noble) | `2.42-4ubuntu2.3` | `2.42-4ubuntu2.4` | [USN-7306-1](https://ubuntu.com/security/notices/USN-7306-1) | Alternativa |
| [CVE-2024-38428](CVE-2024-38428/scenario.md) | `wget` | 24.04 LTS (noble) | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.1` | [USN-6852-1](https://ubuntu.com/security/notices/USN-6852-1) | Alternativa |

## Recomendação para o primeiro caso experimental

**CVE-2025-1372 (`elfutils`)** é a candidata recomendada após aprovação.

Justificativa breve:

1. Pacote utilitário local; a AMI Ubuntu 24.04 padrão tipicamente não depende dele como serviço de rede, o que facilita instalar de propósito a versão vulnerável sem abrir portas.
2. USN e OSV da Canonical publicam versão corrigida explícita (`0.190-1.1ubuntu0.1`) e lista de versões afetadas em `noble`.
3. A eficácia da remediação se prova só com comparação de versão de pacote — independente de qualquer resposta de modelo generativo e sem PoC de exploração.
4. A correção está no canal público de segurança (não exige Ubuntu Pro).

## Próximo passo (somente após aprovação)

1. O autor escolhe **uma** CVE (ou rejeita as três e pede nova rodada).
2. Só então se autoriza a preparação do estado vulnerável na infraestrutura da Fase 1, com os interruptores de recurso pago e as frases de autorização já documentadas.
3. Geração de script por GPT, execução e medição ficam para as fases seguintes e **não** fazem parte desta entrega.

## Aviso sobre backports

No Ubuntu, o número de versão “aparente” do upstream pode parecer antigo e ainda assim já conter o patch de segurança. A comparação válida é sempre a **versão do pacote Debian/Ubuntu** publicada no CVE Tracker / USN / OSV para o release (`noble`), não o número upstream isolado.