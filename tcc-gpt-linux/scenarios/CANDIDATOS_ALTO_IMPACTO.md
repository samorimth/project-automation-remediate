# Candidatos de alto impacto — Ubuntu (≈2021–2026)

Pesquisa para escolher CVEs de **maior impacto / notoriedade** alinhados ao lab do TCC.  
**Fontes:** Ubuntu CVE Tracker, Ubuntu Security Notices (USN), páginas oficiais Canonical.  
**Data da consulta:** 21 de novembro de 2026. **Nenhuma CVE ou score inventado.**

## Critérios de “Fit para ESTE lab”

| Fit | Significado |
| --- | --- |
| **Alto** | USN Canonical; remediação por `apt`; verificação por versão de pacote; reproduzível em 22.04/24.04 sem PoC de exploração |
| **Médio** | Impacto alto e USN ok, mas kernel (pin/reboot), downgrade histórico difícil, ou SO alvo só parcialmente afetado |
| **Baixo** | Famoso, porém 22.04/24.04 não afetados no tracker, ou Ubuntu released “Not affected”, ou sucesso dependeria de exploit |

**Já no portfólio / feito** (marcar e não reescolher como “novo”):  
CVE-2024-38428 (`wget`), CVE-2024-32487 (`less`), CVE-2024-11053 (`curl`), CVE-2024-5742 (`nano`), CVE-2025-1372 (`elfutils`), CVE-2025-48384 (`git`).

Reservas já documentadas no inventário: `binutils`, `libpng`, `tar`, `rsync` — ver [`README.md`](README.md) / [`PORTFOLIO_10_LABS.md`](PORTFOLIO_10_LABS.md).

**Nenhum ambiente foi preparado nesta pesquisa.**

---

## Tabela — candidatos de alto impacto (ordenados por ano, depois impacto)

| CVE | Ano | Componente | Severidade (Ubuntu / NVD) | Problema (1 frase) | USN / Canonical | Fit lab | Motivo do fit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [CVE-2021-3156](https://ubuntu.com/security/CVE-2021-3156) (Baron Samedit) | 2021 | `sudo` | Ubuntu **High** · NVD **7.8** | Falha no `sudo`/`sudoedit` permite que usuário local vire administrador. | [USN-4705-1](https://ubuntu.com/security/notices/USN-4705-1) | **Baixo** | Altíssimo impacto histórico; releases 22.04/24.04 já nasceram corrigidas no tracker — lab atual exigiria pacote/SO mais antigo. |
| [CVE-2021-3493](https://ubuntu.com/security/CVE-2021-3493) (OverlayFS) | 2021 | kernel / OverlayFS | Ubuntu **High** · NVD **8.8** | Bug no OverlayFS permite escalar privilégios locais no Ubuntu. | [USN-4917-1](https://ubuntu.com/security/notices/USN-4917-1) (também USN-4916-1) | **Baixo** | Kernel + 22.04/24.04 **Not affected** no tracker; difícil pinar versão vulnerável no alvo LTS atual. |
| [CVE-2021-33909](https://ubuntu.com/security/CVE-2021-33909) (Sequoia) | 2021 | kernel | Ubuntu **High** · NVD **7.8** | Overflow no sistema de arquivos virtual pode dar root a usuário local. | [USN-5016-1](https://ubuntu.com/security/notices/USN-5016-1) (série USN-501x) | **Baixo** | Kernel; 22.04/24.04 **Not affected**. |
| [CVE-2021-4034](https://ubuntu.com/security/CVE-2021-4034) (PwnKit / polkit) | 2021–2022 | `policykit-1` / `pkexec` | Ubuntu **High** · NVD **7.8** | Ferramenta de “pedir permissão de admin” maltrata argumentos e pode virar root. | [USN-5252-1](https://ubuntu.com/security/notices/USN-5252-1) | **Médio** | Pacote userland + USN; verificação por versão ok **sem PoC**. Jammy já traz versão corrigida de fábrica — precisa `.deb` histórico (ex. focal) no lab 22.04/24.04. |
| [CVE-2022-0847](https://ubuntu.com/security/CVE-2022-0847) (Dirty Pipe) | 2022 | kernel (pipes) | Ubuntu **High** · NVD **7.8** | Usuário local pode sobrescrever arquivos “só leitura” via pipe e escalar privilégios. | [USN-5317-1](https://ubuntu.com/security/notices/USN-5317-1) · [KB DirtyPipe](https://ubuntu.com/security/vulnerabilities/dirtypipe) | **Baixo** | Muito famoso; 22.04/24.04 **Not affected**; kernel + reboot; pin histórico difícil. |
| [CVE-2023-0386](https://ubuntu.com/security/CVE-2023-0386) (OverlayFS) | 2023 | kernel / OverlayFS | Ubuntu **High** · NVD **7.8** | Cópia de arquivo com capacidades no OverlayFS pode elevar privilégios. | [USN-6025-1](https://ubuntu.com/security/notices/USN-6025-1) (jammy) · [USN-6043-1](https://ubuntu.com/security/notices/USN-6043-1) | **Médio** | Bom para **22.04**; 24.04 **Not affected**; kernel exige pin + reboot; lab sem PoC ainda verifica versão do kernel. |
| [CVE-2023-2640](https://ubuntu.com/security/CVE-2023-2640) + [CVE-2023-32629](https://ubuntu.com/security/CVE-2023-32629) (GameOver(lay)) | 2023 | kernel / OverlayFS (Ubuntu) | Ubuntu **High** · NVD **7.8** | Falhas Ubuntu-específicas no OverlayFS permitem virar “quase root” localmente. | [USN-6250-1](https://ubuntu.com/security/notices/USN-6250-1) · [USN-6251-1](https://ubuntu.com/security/notices/USN-6251-1) | **Médio** | Altíssimo impacto em cloud Ubuntu; kernel HWE/variantes; 24.04 **Not affected**; pin + reboot. |
| [CVE-2023-4911](https://ubuntu.com/security/CVE-2023-4911) (Looney Tunables) | 2023 | `glibc` / `ld.so` | Ubuntu **High** · NVD **7.8** | Variável `GLIBC_TUNABLES` maltratada pode dar root via programas setuid. | [USN-6409-1](https://ubuntu.com/security/notices/USN-6409-1) | **Alto** | Pacote `libc6` onipresente; USN clara; verifica por versão; **22.04** afetado; 24.04 já com fix na linha de release — preferir jammy para estado vulnerável histórico; reboot após update. |
| [CVE-2023-6246](https://ubuntu.com/security/CVE-2023-6246) (glibc syslog) | 2024* | `glibc` | Ubuntu **Medium** · NVD **7.8** | Overflow em `syslog`/`__vsyslog_internal` pode crashar ou escalar privilégios. | [USN-6620-1](https://ubuntu.com/security/notices/USN-6620-1) | **Baixo** | Impacto real, mas Ubuntu **Medium**; 22.04 **Not affected**; 24.04 corrigido na versão de release. |
| [CVE-2024-1086](https://ubuntu.com/security/CVE-2024-1086) (netfilter / nf_tables) | 2024 | kernel / netfilter | Ubuntu **High** · NVD **7.8** | Use-after-free no filtro de rede local pode dar root. | [USN-6707-1](https://ubuntu.com/security/notices/USN-6707-1) (também USN-6700-1 / 6702) | **Médio** | Alto impacto (KEV/notoriedade); **22.04** sim; **24.04 Not affected**; kernel + reboot. |
| [CVE-2024-3094](https://ubuntu.com/security/CVE-2024-3094) (xz / liblzma backdoor) | 2024 | `xz-utils` | Ubuntu **Critical** · NVD **10.0** | Backdoor no xz poderia comprometer sshd — mas **não entrou** em releases Ubuntu. | Tracker: [CVE-2024-3094](https://ubuntu.com/security/CVE-2024-3094) (sem USN de release afetado) | **Baixo** | Notório mundialmente; Canonical: releases LTS **Not affected** (só `noble-proposed` removido). Sem lab útil no modelo “apt fix em 22.04/24.04”. |
| [CVE-2024-6387](https://ubuntu.com/security/CVE-2024-6387) (regreSSHion) | 2024 | `openssh` / `sshd` | Ubuntu **High** · NVD **8.1** | Race no servidor SSH pode permitir acesso remoto sem credenciais. | [USN-6859-1](https://ubuntu.com/security/notices/USN-6859-1) · [blog Canonical](https://ubuntu.com/blog/ubuntu-regresshion-security-fix) | **Alto** | Perfeito para o lab: 22.04 e 24.04 com fix USN; remediação `apt install openssh-server`; sucesso = versão ≥ corrigida (**sem** PoC). |
| [CVE-2024-47176](https://ubuntu.com/security/CVE-2024-47176) (cups-browsed) | 2024 | `cups-browsed` | Ubuntu **Medium** · NVD **5.3** (cadeia RCE em combinação) | Serviço de descoberta de impressoras confia demais na rede e, com outras falhas, pode levar a código remoto. | [USN-7042-1](https://ubuntu.com/security/notices/USN-7042-1) (melhorias USN-7042-2/3) | **Médio** | Bom em **24.04** (pacote dedicado); remediação por update; prioridade Ubuntu só Medium; lab sem exploração ainda funciona por versão. |
| [CVE-2024-48990](https://ubuntu.com/security/CVE-2024-48990) (needrestart; família 48991/48992/11003) | 2024 | `needrestart` | Ubuntu **High** · NVD **7.8** | Ferramenta que reinicia serviços após update pode ser enganada e executar código como root. | [USN-7117-1](https://ubuntu.com/security/notices/USN-7117-1) · [blog Canonical](https://ubuntu.com/blog/needrestart-local-privilege-escalation) | **Alto** | Excelente fit: instalado por padrão em Server 22.04+; USN clara; `apt` + versão; 22.04 e 24.04; sem PoC. |
| [CVE-2024-12084](https://ubuntu.com/security/CVE-2024-12084) | 2024 | `rsync` | Ubuntu **High** · NVD **9.8** | Overflow no protocolo rsync (risco grave se daemon/cliente vulnerável). | [USN-7206-1](https://ubuntu.com/security/notices/USN-7206-1) | **Alto**† | Já é **reserva** do inventário; remediação por versão; lab não precisa daemon/PoC. |
| [CVE-2025-26465](https://ubuntu.com/security/CVE-2025-26465) | 2025 | `openssh` (cliente) | Ubuntu **Medium** · NVD **6.8** | Com opção DNS de host key, cliente pode aceitar servidor falso (MITM em cenário raro). | [USN-7270-1](https://ubuntu.com/security/notices/USN-7270-1) | **Baixo** | USN ok, mas impacto/prioridade menores que regreSSHion; opção não default. |
| [CVE-2025-48384](https://ubuntu.com/security/CVE-2025-48384) | 2025 | `git` | Ubuntu **High** · NVD **8.0** | Git trata mal caminhos/submódulo; risco de código indesejado. | [USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1) | **Alto**† | **Já no portfólio** (pendente aprovação). |

\*Publicação/disclosure em 2024; CVE id 2023.  
†Já no inventário do repositório (portfólio ou reserva).

---

## Já no portfólio (marcar — impacto “médio/útil”, não os maiores headlines)

| CVE | Ano | Pacote | Ubuntu / NVD | USN | Status no TCC |
| --- | --- | --- | --- | --- | --- |
| [CVE-2024-38428](https://ubuntu.com/security/CVE-2024-38428) | 2024 | `wget` | medium / 9.1 | [USN-6852-1](https://ubuntu.com/security/notices/USN-6852-1) | **EXECUTADO — SUCESSO** |
| [CVE-2024-32487](https://ubuntu.com/security/CVE-2024-32487) | 2024 | `less` | medium / 8.6 | [USN-6756-1](https://ubuntu.com/security/notices/USN-6756-1) | **EXECUTADO — FALHA** |
| [CVE-2024-11053](https://ubuntu.com/security/CVE-2024-11053) | 2024 | `curl` | low / 3.4 | [USN-7162-1](https://ubuntu.com/security/notices/USN-7162-1) | portfólio / pendente |
| [CVE-2024-5742](https://ubuntu.com/security/CVE-2024-5742) | 2024 | `nano` | low / 6.7 | [USN-7064-1](https://ubuntu.com/security/notices/USN-7064-1) | portfólio / pendente |
| [CVE-2025-1372](https://ubuntu.com/security/CVE-2025-1372) | 2025 | `elfutils` | medium / ~5.3 | [USN-7369-1](https://ubuntu.com/security/notices/USN-7369-1) | portfólio / pendente |
| [CVE-2025-48384](https://ubuntu.com/security/CVE-2025-48384) | 2025 | `git` | high / 8.0 | [USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1) | portfólio / pendente |

---

## Recomendação rápida para o TCC (só escolha, sem preparar ambiente)

Se quiser **substituir ou complementar** CVEs “menores” do portfólio por headlines de impacto, priorize **Fit Alto**:

1. **CVE-2024-6387** (`openssh`) — remoto, High, 22.04+24.04, apt + versão  
2. **CVE-2024-48990** (`needrestart`) — root local, High, Server default, apt + versão  
3. **CVE-2023-4911** (`glibc`) — High, ótimo em **22.04**; reboot  
4. Manter **CVE-2025-48384** (`git`) e/ou reserva **CVE-2024-12084** (`rsync`)  

Kernel (Dirty Pipe, OverlayFS, GameOver(lay), netfilter): ótimos para **capítulo de impacto**, fracos como lab “pin + verify” sob as regras atuais → **Médio/Baixo**.

PwnKit / Baron Samedit / Dirty Pipe: citar na revisão bibliográfica; **não** priorizar como lab em 22.04/24.04.

---

## Fontes consultadas

- [Ubuntu CVE Tracker](https://ubuntu.com/security/)  
- [Ubuntu Security Notices](https://ubuntu.com/security/notices)  
- Páginas CVE individuais listadas na tabela  
- Blogs Canonical: [regreSSHion](https://ubuntu.com/blog/ubuntu-regresshion-security-fix), [needrestart](https://ubuntu.com/blog/needrestart-local-privilege-escalation), [DirtyPipe KB](https://ubuntu.com/security/vulnerabilities/dirtypipe)
