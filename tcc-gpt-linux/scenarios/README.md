# Cenários CVE — Fase 2 (propostas)

Este diretório registra candidatos a CVE para o primeiro experimento do laboratório. A Fase 2, neste ponto, **apenas propõe** CVEs reais para **aprovação explícita** do autor do TCC. Nada de AMI vulnerável, NAT, `terraform apply` ou chamada OpenAI até essa escolha.

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

O autor deve escolher **uma** CVE nesta lista antes de qualquer preparação de ambiente vulnerável.

## Critérios usados na seleção

- Documentação oficial da Canonical (Ubuntu CVE Tracker e/ou USN).
- Versões vulnerável e corrigida conhecidas para Ubuntu 24.04 LTS (`noble`), alinhada à AMI padrão da Fase 1.
- Remediação por atualização de pacote (`apt`), sem exploração ativa.
- Verificação independente antes/depois via `dpkg -s`, `apt-cache policy` e comparação com a versão corrigida publicada.
- Pacote instalável (ou reinstalável em versão antiga) em EC2 privada, sem expor serviço à Internet.
- Correção disponível no repositório público (sem depender de Ubuntu Pro / ESM).
- Diversidade de pacotes (utilitários locais, cliente de rede, biblioteca, VCS), não só clones de `binutils`/`elfutils`.

Fontes: [Ubuntu CVE Tracker](https://ubuntu.com/security/), [Ubuntu Security Notices](https://ubuntu.com/security/notices), [OSV / USN JSON](https://osv.dev/) e, complementarmente, NVD. Versões vulneráveis são as publicadas no OSV da Canonical para `Ubuntu:24.04:LTS`; a versão de preparação sugerida é a última vulnerável registrada para `noble`.

## Candidatos (~10)

| CVE | Pacote | Prioridade Ubuntu | NVD CVSS | Versão vulnerável (ex.) | Versão corrigida | USN | Reprodutibilidade | Impacto (1 linha) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [CVE-2025-1372](CVE-2025-1372/scenario.md) | `elfutils` | medium | 5.3 | `0.190-1.1build4.1` | `0.190-1.1ubuntu0.1` | [USN-7369-1](https://ubuntu.com/security/notices/USN-7369-1) | fácil | Overflow local em `eu-readelf` ao processar arquivo malicioso (DoS). |
| [CVE-2025-0840](CVE-2025-0840/scenario.md) | `binutils` | medium | 5.0 | `2.42-4ubuntu2.3` | `2.42-4ubuntu2.4` | [USN-7306-1](https://ubuntu.com/security/notices/USN-7306-1) | média | Overflow em `objdump` com entrada inadequada; risco de falha/código. |
| [CVE-2024-38428](CVE-2024-38428/scenario.md) | `wget` | medium | 9.1 | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.1` | [USN-6852-1](https://ubuntu.com/security/notices/USN-6852-1) | fácil | `userinfo` de URI mal interpretado; conexão a host inesperado. |
| [CVE-2024-11053](CVE-2024-11053/scenario.md) | `curl` | low | 3.4 | `8.5.0-2ubuntu10.5` | `8.5.0-2ubuntu10.6` | [USN-7162-1](https://ubuntu.com/security/notices/USN-7162-1) | fácil | Vazamento de senha `.netrc` em redirecionamento HTTP. |
| [CVE-2024-32487](CVE-2024-32487/scenario.md) | `less` | medium | 8.6 | `590-2ubuntu2` | `590-2ubuntu2.1` | [USN-6756-1](https://ubuntu.com/security/notices/USN-6756-1) | fácil | Execução de comando via newline em nome de arquivo no pager. |
| [CVE-2024-5742](CVE-2024-5742/scenario.md) | `nano` | low | 6.7 | `7.2-2build1` | `7.2-2ubuntu0.1` | [USN-7064-1](https://ubuntu.com/security/notices/USN-7064-1) | fácil | Escalação via arquivo temporário inseguro se `nano` for interrompido. |
| [CVE-2025-48384](CVE-2025-48384/scenario.md) | `git` | high | 8.0 | `1:2.43.0-1ubuntu7.2` | `1:2.43.0-1ubuntu7.3` | [USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1) | média | Falha no tratamento de CRLF em config/submódulo; risco de código. |
| [CVE-2025-64505](CVE-2025-64505/scenario.md) | `libpng1.6` | medium | 6.1 | `1.6.43-5build1` | `1.6.43-5ubuntu0.1` | [USN-7924-1](https://ubuntu.com/security/notices/USN-7924-1) | média | Over-read em heap ao processar PNG com índices de paleta inválidos. |
| [CVE-2025-45582](CVE-2025-45582/scenario.md) | `tar` | medium | 4.1 | `1.35+dfsg-3ubuntu0.1` | `1.35+dfsg-3ubuntu0.2` | [USN-8510-1](https://ubuntu.com/security/notices/USN-8510-1) | média | Travessia/overwrite via symlink em extrações sequenciais de TAR. |
| [CVE-2024-12084](CVE-2024-12084/scenario.md) | `rsync` | high | 9.8 | `3.2.7-1ubuntu1` | `3.2.7-1ubuntu1.1` | [USN-7206-1](https://ubuntu.com/security/notices/USN-7206-1) | média | Overflow em heap no protocolo rsync; lab usa só versão, sem daemon. |

Todas as fichas estão com status **pendente**. Detalhes, links oficiais e procedimentos previstos (ainda não executados) estão em `scenarios/<CVE>/scenario.md`.

## Quais são as mais fáceis para o 1º experimento

Ordem sugerida só para **preparação de laboratório** (downgrade/pin + verificação por versão), não por gravidade:

1. **CVE-2024-32487 (`less`)** — pacote único, pinagem simples, USN claro.
2. **CVE-2024-5742 (`nano`)** — idem; cenário de ataque incomum, mas ótimo para medição por versão.
3. **CVE-2024-11053 (`curl`)** / **CVE-2024-38428 (`wget`)** — clientes de rede, sem abrir serviço; AMI atual exigirá *downgrade* histórico.
4. **CVE-2025-1372 (`elfutils`)** — utilitário local; boa candidata “clássica” já documentada na 1ª rodada.

Evitar como **primeiro** caso (mais atrito operacional): `binutils` (vários `.deb` alinhados), `git` (conjunto de pacotes), `libpng1.6`/`tar`/`rsync` (dependências ou pacote essencial / tentação de expor serviço).

## Próximo passo (somente após aprovação)

1. O autor escolhe **uma** CVE (ou rejeita a lista e pede nova rodada).
2. Só então se autoriza a preparação do estado vulnerável na infraestrutura da Fase 1, com os interruptores de recurso pago e as frases de autorização já documentadas.
3. Geração de script por GPT, execução e medição ficam para as fases seguintes e **não** fazem parte desta entrega.

## Aviso sobre backports e pacotes históricos

No Ubuntu, o número “aparente” do upstream pode parecer antigo e ainda assim já conter o patch de segurança (ex.: `5.6.1+really5.4.5-…` em `xz-utils`). A comparação válida é sempre a **versão do pacote Debian/Ubuntu** no CVE Tracker / USN / OSV para `noble`, não o número upstream isolado. AMIs recentes já trazem correções: a preparação típica é obter `.deb` no Launchpad/pool histórico e fazer *downgrade* pinado, com risco de dependências quebradas se o conjunto de pacotes binários não ficar coerente.
