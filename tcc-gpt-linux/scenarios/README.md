# Cenários do laboratório — inventário e portfólio

Este diretório registra candidatos a laboratório. O **portfólio atualizado** (seleção do usuário) está em [`PORTFOLIO_10_LABS.md`](PORTFOLIO_10_LABS.md). Descrições acessíveis: [`DESCRICOES_NAOTECNICAS.md`](DESCRICOES_NAOTECNICAS.md). Alto impacto: [`CANDIDATOS_ALTO_IMPACTO.md`](CANDIDATOS_ALTO_IMPACTO.md). Histórico CONFIG: [`CONFIG_CANDIDATOS_EXTRA.md`](CONFIG_CANDIDATOS_EXTRA.md).

## Estado em 21 de novembro de 2026 (seleção completa)

| Item | Situação |
| --- | --- |
| Portfólio | **2 CVE executadas** + **6 CVE selecionadas** (pendentes) + **4 CONFIG selecionadas/aprovadas** → **12 labs** (8 CVE + 4 CONFIG) |
| CVE executadas | **CVE-2024-38428 (`wget`) — SUCESSO**; **CVE-2024-32487 (`less`) — FALHA** |
| CVE selecionadas | `CVE-2024-6387` (openssh), `CVE-2024-48990` (needrestart), `CVE-2023-4911` (glibc), `CVE-2024-12084` (rsync), `CVE-2025-48384` (git), `CVE-2024-11053` (curl) |
| CONFIG selecionadas (4/4) | `CONFIG-SSH-PERMIT-ROOT`, `CONFIG-NGINX-AUTOINDEX`, `CONFIG-FAIL2BAN-ABSENT`, `CONFIG-SUDOERS-NOPASSWD` |
| CONFIG reserva | demais propostas em `CONFIG_CANDIDATOS_EXTRA.md` (não escolhidas) |
| Substituídas (fora da seleção) | `CVE-2024-5742` (nano), `CVE-2025-1372` (elfutils) → reserva |
| Recursos AWS agora | nenhuma pilha do lab ligada; não aplicar Terraform sem autorização |
| Resultado inventado | **não** |

**Gates:** aguardar autorização explícita antes de preparar ambiente vulnerável; sem inventar CVE/versão; sem exploração ativa; EC2 privada; Ubuntu 24.04 (exceto nota jammy para glibc); modelo oficial `OPENAI_MODEL` quando houver geração. <!-- pragma: allowlist secret -->

## Portfólio (resumo)

| # | ID | Tipo | Status |
| --- | --- | --- | --- |
| 1 | [CVE-2024-38428](CVE-2024-38428/scenario.md) | CVE | **EXECUTADO — SUCESSO** |
| 2 | [CVE-2024-32487](CVE-2024-32487/scenario.md) | CVE | **EXECUTADO — FALHA** |
| 3 | [CONFIG-SSH-PERMIT-ROOT](CONFIG-SSH-PERMIT-ROOT/scenario.md) | CONFIG | **SELECIONADA / APROVADA** / pendente preparação |
| 4 | [CONFIG-NGINX-AUTOINDEX](CONFIG-NGINX-AUTOINDEX/scenario.md) | CONFIG | **SELECIONADA / APROVADA** / pendente preparação |
| 5 | [CONFIG-FAIL2BAN-ABSENT](CONFIG-FAIL2BAN-ABSENT/scenario.md) | CONFIG | **SELECIONADA / APROVADA** / pendente preparação |
| 6 | [CONFIG-SUDOERS-NOPASSWD](CONFIG-SUDOERS-NOPASSWD/scenario.md) | CONFIG | **SELECIONADA / APROVADA** / pendente preparação |
| 7 | CVE-2024-6387 (`openssh`) | CVE | **SELECIONADA** / ficha a criar |
| 8 | CVE-2024-48990 (`needrestart`) | CVE | **SELECIONADA** / ficha a criar |
| 9 | CVE-2023-4911 (`glibc`) | CVE | **SELECIONADA** / ficha a criar |
| 10 | [CVE-2024-12084](CVE-2024-12084/scenario.md) | CVE | **SELECIONADA** (antes reserva) |
| 11 | [CVE-2025-48384](CVE-2025-48384/scenario.md) | CVE | **SELECIONADA** |
| 12 | [CVE-2024-11053](CVE-2024-11053/scenario.md) | CVE | **SELECIONADA** |

Detalhes e versões Canonical: [`PORTFOLIO_10_LABS.md`](PORTFOLIO_10_LABS.md).

## Critérios usados na seleção (CVE)

- Documentação oficial da Canonical (Ubuntu CVE Tracker e/ou USN).
- Versões vulnerável e corrigida conhecidas (24.04; jammy para Looney Tunables).
- Remediação por atualização de pacote (`apt`), sem exploração ativa.
- Verificação independente antes/depois via `dpkg -s` / comparação de versão.
- Pacote instalável em EC2 privada, sem expor serviço à Internet.
- Correção disponível no repositório público (sem depender de Ubuntu Pro / ESM), salvo nota explícita.

## Critérios dos casos CONFIG

- Rotulados explicitamente como **CONFIG** (não CVE).
- Estado inseguro e seguro observáveis por inspeção.
- Remediáveis sem PoC ofensiva; reversíveis; adequados a Ubuntu 24.04 privado.

Fontes CVE: [Ubuntu CVE Tracker](https://ubuntu.com/security/), [Ubuntu Security Notices](https://ubuntu.com/security/notices), [OSV / USN JSON](https://osv.dev/).

## Tabela completa de candidatos CVE (inclui reservas)

| CVE | Status | Pacote | Prioridade Ubuntu | NVD CVSS | Versão vulnerável (ex.) | Versão corrigida | USN | Reprodutibilidade | Impacto (1 linha) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [CVE-2024-38428](CVE-2024-38428/scenario.md) | **executado — sucesso** | `wget` | medium | 9.1 | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.1` | [USN-6852-1](https://ubuntu.com/security/notices/USN-6852-1) | fácil | `userinfo` de URI mal interpretado; conexão a host inesperado. |
| [CVE-2024-32487](CVE-2024-32487/scenario.md) | **executado — falha** | `less` | medium | 8.6 | `590-2ubuntu2` | `590-2ubuntu2.1` | [USN-6756-1](https://ubuntu.com/security/notices/USN-6756-1) | fácil | Execução de comando via newline em nome de arquivo no pager. |
| CVE-2024-6387 | **selecionada** | `openssh-server` | high | 8.1 | `1:9.6p1-3ubuntu13` | `1:9.6p1-3ubuntu13.3` | [USN-6859-1](https://ubuntu.com/security/notices/USN-6859-1) | fácil | Race em sinais do sshd (regreSSHion); lab só por versão. |
| CVE-2024-48990 | **selecionada** | `needrestart` | high | 7.8 | `3.6-7ubuntu4` | `3.6-7ubuntu4.3` | [USN-7117-1](https://ubuntu.com/security/notices/USN-7117-1) | fácil | Escalação local via ambiente (ex. PYTHONPATH) no needrestart. |
| CVE-2023-4911 | **selecionada** | `libc6` | high | 7.8 | jammy `2.35-0ubuntu3.3` | jammy `2.35-0ubuntu3.4` | [USN-6409-1](https://ubuntu.com/security/notices/USN-6409-1) | média† | Overflow em `GLIBC_TUNABLES` / ld.so (Looney Tunables). |
| [CVE-2024-12084](CVE-2024-12084/scenario.md) | **selecionada** | `rsync` | high | 9.8 | `3.2.7-1ubuntu1` | `3.2.7-1ubuntu1.1` | [USN-7206-1](https://ubuntu.com/security/notices/USN-7206-1) | média | Overflow em heap no protocolo rsync; lab usa só versão, sem daemon. |
| [CVE-2025-48384](CVE-2025-48384/scenario.md) | **selecionada** | `git` | high | 8.0 | `1:2.43.0-1ubuntu7.2` | `1:2.43.0-1ubuntu7.3` | [USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1) | média | Falha no tratamento de CRLF em config/submódulo; risco de código. |
| [CVE-2024-11053](CVE-2024-11053/scenario.md) | **selecionada** | `curl` | low | 3.4 | `8.5.0-2ubuntu10.5` | `8.5.0-2ubuntu10.6` | [USN-7162-1](https://ubuntu.com/security/notices/USN-7162-1) | fácil | Vazamento de senha `.netrc` em redirecionamento HTTP. |
| [CVE-2024-5742](CVE-2024-5742/scenario.md) | reserva (substituída) | `nano` | low | 6.7 | `7.2-2build1` | `7.2-2ubuntu0.1` | [USN-7064-1](https://ubuntu.com/security/notices/USN-7064-1) | fácil | Escalação via arquivo temporário inseguro se `nano` for interrompido. |
| [CVE-2025-1372](CVE-2025-1372/scenario.md) | reserva (substituída) | `elfutils` | medium | 5.3* | `0.190-1.1build4.1` | `0.190-1.1ubuntu0.1` | [USN-7369-1](https://ubuntu.com/security/notices/USN-7369-1) | fácil | Overflow local em `eu-readelf` ao processar arquivo malicioso (DoS). |
| [CVE-2025-0840](CVE-2025-0840/scenario.md) | reserva | `binutils` | medium | 5.0 | `2.42-4ubuntu2.3` | `2.42-4ubuntu2.4` | [USN-7306-1](https://ubuntu.com/security/notices/USN-7306-1) | média | Overflow em `objdump` com entrada inadequada; risco de falha/código. |
| [CVE-2025-64505](CVE-2025-64505/scenario.md) | reserva | `libpng1.6` | medium | 6.1 | `1.6.43-5build1` | `1.6.43-5ubuntu0.1` | [USN-7924-1](https://ubuntu.com/security/notices/USN-7924-1) | média | Over-read em heap ao processar PNG com índices de paleta inválidos. |
| [CVE-2025-45582](CVE-2025-45582/scenario.md) | reserva | `tar` | medium | 4.1 | `1.35+dfsg-3ubuntu0.1` | `1.35+dfsg-3ubuntu0.2` | [USN-8510-1](https://ubuntu.com/security/notices/USN-8510-1) | média | Travessia/overwrite via symlink em extrações sequenciais de TAR. |

\*CVSS NVD para CVE-2025-1372 conforme ficha já registrada.  
†CVE-2023-4911: **noble** Fixed na release (`2.38-1ubuntu6`); preparar estado vulnerável em **jammy** (ou documentar limitação). Versões revalidadas em 21/11/2026.

## Artefatos de preparação (já existentes)

| Lab | Arquivos |
| --- | --- |
| CVE-2024-38428 | `scenario.md`, `prepare.sh`, `verify_*.sh`, `evidence/` |
| CVE-2024-32487 | `scenario.md`, `prepare.sh`, `verify_*.sh` |
| CONFIG-* (originais) | apenas `scenario.md` (stub) até aprovação/preparação |
| CVE selecionadas com ficha | `curl`, `git`, `rsync` — `scenario.md`; openssh/needrestart/glibc — a criar |
| Demais | apenas `scenario.md` até aprovação |

## Próximo passo

1. Seleção completa: **8 CVE + 4 CONFIG** refletidas.  
2. Aguardar autorização do usuário para **iniciar implementação** (CONFIG vs. CVE).  
3. **Não** há `terraform apply`, geração OpenAI nem AMI vulnerável nesta fase.

## Aviso sobre backports e pacotes históricos

No Ubuntu, o número “aparente” do upstream pode parecer antigo e ainda assim já conter o patch de segurança. A comparação válida é sempre a **versão do pacote Debian/Ubuntu** no CVE Tracker / USN / OSV, não o número upstream isolado. AMIs recentes já trazem correções: a preparação típica é obter `.deb` no Launchpad/archive.ubuntu.com e fazer *downgrade* pinado.
