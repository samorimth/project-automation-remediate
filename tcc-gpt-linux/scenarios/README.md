# Cenários do laboratório — inventário e portfólio

Este diretório registra candidatos a laboratório. O **portfólio oficial proposto de 10 labs** (6 CVE + 4 CONFIG) está em [`PORTFOLIO_10_LABS.md`](PORTFOLIO_10_LABS.md). Descrições acessíveis (problema / exemplo prático / correção) para leitores não técnicos: [`DESCRICOES_NAOTECNICAS.md`](DESCRICOES_NAOTECNICAS.md). Lista de CVEs de **alto impacto** (≈2021–2026) com fit Alto/Médio/Baixo para este lab: [`CANDIDATOS_ALTO_IMPACTO.md`](CANDIDATOS_ALTO_IMPACTO.md).

## Estado em 21 de novembro de 2026

| Item | Situação |
| --- | --- |
| Portfólio 10 labs | proposto em `PORTFOLIO_10_LABS.md` — **2 executados**, **8 pendentes de aprovação** |
| CVE executadas | **CVE-2024-38428 (`wget`) — SUCESSO**; **CVE-2024-32487 (`less`) — FALHA** |
| CONFIG | 4 stubs novos (`CONFIG-*`) — **não são CVE**; pendentes de aprovação |
| CVE adicionais do portfólio | `CVE-2024-11053`, `CVE-2024-5742`, `CVE-2025-1372`, `CVE-2025-48384` — fichas existentes; status **candidato do portfólio / pendente aprovação** |
| Reservas (fora dos 10) | `CVE-2025-0840`, `CVE-2025-64505`, `CVE-2025-45582`, `CVE-2024-12084` |
| Recursos AWS agora | nenhuma pilha do lab ligada; não aplicar Terraform sem autorização |
| Resultado inventado | **não** |

**Gates:** apresentar candidatos e aguardar aprovação antes de preparar ambiente vulnerável; sem inventar CVE/versão; sem exploração ativa; EC2 privada; Ubuntu 24.04; modelo oficial `OPENAI_MODEL` quando houver geração. <!-- pragma: allowlist secret -->

## Portfólio (resumo)

| # | ID | Tipo | Status |
| --- | --- | --- | --- |
| 1 | [CVE-2024-38428](CVE-2024-38428/scenario.md) | CVE | **EXECUTADO — SUCESSO** |
| 2 | [CVE-2024-32487](CVE-2024-32487/scenario.md) | CVE | **EXECUTADO — FALHA** |
| 3 | [CONFIG-SSH-PERMIT-ROOT](CONFIG-SSH-PERMIT-ROOT/scenario.md) | CONFIG | pendente aprovação |
| 4 | [CONFIG-WORLD-WRITABLE-SENSITIVE](CONFIG-WORLD-WRITABLE-SENSITIVE/scenario.md) | CONFIG | pendente aprovação |
| 5 | [CONFIG-CRON-WEAK-PERMS](CONFIG-CRON-WEAK-PERMS/scenario.md) | CONFIG | pendente aprovação |
| 6 | [CONFIG-LOCAL-HTTP-BIND](CONFIG-LOCAL-HTTP-BIND/scenario.md) | CONFIG | pendente aprovação |
| 7 | [CVE-2024-11053](CVE-2024-11053/scenario.md) | CVE | candidato portfólio / pendente aprovação |
| 8 | [CVE-2024-5742](CVE-2024-5742/scenario.md) | CVE | candidato portfólio / pendente aprovação |
| 9 | [CVE-2025-1372](CVE-2025-1372/scenario.md) | CVE | candidato portfólio / pendente aprovação |
| 10 | [CVE-2025-48384](CVE-2025-48384/scenario.md) | CVE | candidato portfólio / pendente aprovação |

Detalhes, versões conferidas na Canonical e ordem recomendada: [`PORTFOLIO_10_LABS.md`](PORTFOLIO_10_LABS.md).

## Critérios usados na seleção (CVE)

- Documentação oficial da Canonical (Ubuntu CVE Tracker e/ou USN).
- Versões vulnerável e corrigida conhecidas para Ubuntu 24.04 LTS (`noble`).
- Remediação por atualização de pacote (`apt`), sem exploração ativa.
- Verificação independente antes/depois via `dpkg -s`, `apt-cache policy` e comparação com a versão corrigida publicada.
- Pacote instalável (ou reinstalável em versão antiga) em EC2 privada, sem expor serviço à Internet.
- Correção disponível no repositório público (sem depender de Ubuntu Pro / ESM).
- Diversidade de pacotes (utilitários locais, cliente de rede, biblioteca, VCS).

## Critérios dos casos CONFIG

- Rotulados explicitamente como **CONFIG** (não CVE).
- Estado inseguro e seguro observáveis por inspeção (`sshd -T`, `stat`, `ss`).
- Remediáveis sem PoC ofensiva; reversíveis; adequados a Ubuntu 24.04 privado.

Fontes CVE: [Ubuntu CVE Tracker](https://ubuntu.com/security/), [Ubuntu Security Notices](https://ubuntu.com/security/notices), [OSV / USN JSON](https://osv.dev/).

## Tabela completa de candidatos CVE (inclui reservas)

| CVE | Status | Pacote | Prioridade Ubuntu | NVD CVSS | Versão vulnerável (ex.) | Versão corrigida | USN | Reprodutibilidade | Impacto (1 linha) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [CVE-2024-38428](CVE-2024-38428/scenario.md) | **executado — sucesso** | `wget` | medium | 9.1 | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.1` | [USN-6852-1](https://ubuntu.com/security/notices/USN-6852-1) | fácil | `userinfo` de URI mal interpretado; conexão a host inesperado. |
| [CVE-2024-32487](CVE-2024-32487/scenario.md) | **executado — falha** | `less` | medium | 8.6 | `590-2ubuntu2` | `590-2ubuntu2.1` | [USN-6756-1](https://ubuntu.com/security/notices/USN-6756-1) | fácil | Execução de comando via newline em nome de arquivo no pager. |
| [CVE-2024-11053](CVE-2024-11053/scenario.md) | portfólio / pendente | `curl` | low | 3.4 | `8.5.0-2ubuntu10.5` | `8.5.0-2ubuntu10.6` | [USN-7162-1](https://ubuntu.com/security/notices/USN-7162-1) | fácil | Vazamento de senha `.netrc` em redirecionamento HTTP. |
| [CVE-2024-5742](CVE-2024-5742/scenario.md) | portfólio / pendente | `nano` | low | 6.7 | `7.2-2build1` | `7.2-2ubuntu0.1` | [USN-7064-1](https://ubuntu.com/security/notices/USN-7064-1) | fácil | Escalação via arquivo temporário inseguro se `nano` for interrompido. |
| [CVE-2025-1372](CVE-2025-1372/scenario.md) | portfólio / pendente | `elfutils` | medium | 5.3* | `0.190-1.1build4.1` | `0.190-1.1ubuntu0.1` | [USN-7369-1](https://ubuntu.com/security/notices/USN-7369-1) | fácil | Overflow local em `eu-readelf` ao processar arquivo malicioso (DoS). |
| [CVE-2025-48384](CVE-2025-48384/scenario.md) | portfólio / pendente | `git` | high | 8.0 | `1:2.43.0-1ubuntu7.2` | `1:2.43.0-1ubuntu7.3` | [USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1) | média | Falha no tratamento de CRLF em config/submódulo; risco de código. |
| [CVE-2025-0840](CVE-2025-0840/scenario.md) | reserva | `binutils` | medium | 5.0 | `2.42-4ubuntu2.3` | `2.42-4ubuntu2.4` | [USN-7306-1](https://ubuntu.com/security/notices/USN-7306-1) | média | Overflow em `objdump` com entrada inadequada; risco de falha/código. |
| [CVE-2025-64505](CVE-2025-64505/scenario.md) | reserva | `libpng1.6` | medium | 6.1 | `1.6.43-5build1` | `1.6.43-5ubuntu0.1` | [USN-7924-1](https://ubuntu.com/security/notices/USN-7924-1) | média | Over-read em heap ao processar PNG com índices de paleta inválidos. |
| [CVE-2025-45582](CVE-2025-45582/scenario.md) | reserva | `tar` | medium | 4.1 | `1.35+dfsg-3ubuntu0.1` | `1.35+dfsg-3ubuntu0.2` | [USN-8510-1](https://ubuntu.com/security/notices/USN-8510-1) | média | Travessia/overwrite via symlink em extrações sequenciais de TAR. |
| [CVE-2024-12084](CVE-2024-12084/scenario.md) | reserva | `rsync` | high | 9.8 | `3.2.7-1ubuntu1` | `3.2.7-1ubuntu1.1` | [USN-7206-1](https://ubuntu.com/security/notices/USN-7206-1) | média | Overflow em heap no protocolo rsync; lab usa só versão, sem daemon. |

\*CVSS NVD para CVE-2025-1372 conforme ficha já registrada no repositório; prioridade Ubuntu medium. Versões CVE do portfólio revalidadas nas USN oficiais em 21/11/2026.

## Artefatos de preparação (já existentes)

| Lab | Arquivos |
| --- | --- |
| CVE-2024-38428 | `scenario.md`, `prepare.sh`, `verify_*.sh`, `evidence/` |
| CVE-2024-32487 | `scenario.md`, `prepare.sh`, `verify_*.sh` |
| CONFIG-* | apenas `scenario.md` (stub) até aprovação |
| Demais CVE | apenas `scenario.md` até aprovação |

## Próximo passo

Aprovar quais dos 8 pendentes do portfólio entram na implementação. **Não** há `terraform apply`, geração OpenAI nem AMI vulnerável nesta fase de proposta.

## Aviso sobre backports e pacotes históricos

No Ubuntu, o número “aparente” do upstream pode parecer antigo e ainda assim já conter o patch de segurança. A comparação válida é sempre a **versão do pacote Debian/Ubuntu** no CVE Tracker / USN / OSV para `noble`, não o número upstream isolado. AMIs recentes já trazem correções: a preparação típica é obter `.deb` no Launchpad/archive.ubuntu.com e fazer *downgrade* pinado.
