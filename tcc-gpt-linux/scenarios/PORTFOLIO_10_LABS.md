# Portfólio de laboratórios — seleção atualizada (faltando 1 CONFIG)

**Status geral:** 2 labs **executados**; **6 CVE selecionadas** ainda **pendentes de preparação**; **3 CONFIG selecionadas** (`SSH PermitRootLogin`, `nginx autoindex`, `fail2ban ausente/parado`); falta **1 CONFIG** para completar o bloco de 4.  
**Não** preparar AMI / **não** gerar script GPT / **não** `terraform apply` até autorização explícita.  
**Modelo oficial previsto (quando houver geração):** `OPENAI_MODEL` (mesmo modelo dos experimentos oficiais).   <!-- pragma: allowlist secret -->
**SO alvo:** Ubuntu 24.04 LTS (`noble`), EC2 privada, sem exploração ativa — com nota especial para CVE-2023-4911 (preferência **22.04** para estado vulnerável histórico).  
**Data da proposta:** 21 de novembro de 2026 (atualização: 3/4 CONFIG escolhidas).

Este documento é a ficha de portfólio. Detalhes por lab estão em `scenarios/<id>/scenario.md` (quando existir). Analogias para leitores não técnicos: [`DESCRICOES_NAOTECNICAS.md`](DESCRICOES_NAOTECNICAS.md). Inventário histórico: [`README.md`](README.md). Pesquisa de alto impacto: [`CANDIDATOS_ALTO_IMPACTO.md`](CANDIDATOS_ALTO_IMPACTO.md). **4ª CONFIG (candidatos):** [`CONFIG_CANDIDATOS_EXTRA.md`](CONFIG_CANDIDATOS_EXTRA.md).

**Composição alvo após aprovação da 4ª CONFIG:** **8 CVE + 4 CONFIG = 12 labs** (expansão do desenho original “10 = 6 CVE + 4 CONFIG”, porque o usuário manteve as 2 executadas e selecionou **6** CVE adicionais).

## Inventário pré-proposta (atualizado)

| ID | `scenario.md` | Artefatos prepare/verify | Execução real / seleção |
| --- | --- | --- | --- |
| CVE-2024-38428 (`wget`) | sim | sim | **SUCESSO** (`results/`, `docs/resultados_tcc.md`) |
| CVE-2024-32487 (`less`) | sim | sim | **FALHA** (`docs/resultado_cve_2024_32487.md`) |
| CVE-2024-6387 (`openssh`) | **a criar** | não | **SELECIONADA** — pendente preparação |
| CVE-2024-48990 (`needrestart`) | **a criar** | não | **SELECIONADA** — pendente preparação |
| CVE-2023-4911 (`glibc`) | **a criar** | não | **SELECIONADA** — pendente preparação |
| CVE-2024-12084 (`rsync`) | sim | não | **SELECIONADA** (antes reserva) — pendente preparação |
| CVE-2025-48384 (`git`) | sim | não | **SELECIONADA** — pendente preparação |
| CVE-2024-11053 (`curl`) | sim | não | **SELECIONADA** — pendente preparação |
| CVE-2024-5742 (`nano`) | sim | não | **substituída** → reserva / fora da seleção |
| CVE-2025-1372 (`elfutils`) | sim | não | **substituída** → reserva / fora da seleção |
| CONFIG-SSH-PERMIT-ROOT | sim | stubs | **SELECIONADA** — pendente preparação |
| CONFIG-NGINX-AUTOINDEX | sim | stubs | **SELECIONADA** — pendente preparação |
| CONFIG-FAIL2BAN-ABSENT | sim | stubs | **SELECIONADA** — pendente preparação |
| CONFIG-WORLD-WRITABLE-SENSITIVE | sim | stubs | candidata **4ª vaga** (não confirmada) |
| CONFIG-CRON-WEAK-PERMS | sim | stubs | candidata **4ª vaga** (não confirmada) |
| CONFIG-LOCAL-HTTP-BIND | sim | stubs | candidata **4ª vaga** (não confirmada) |
| CONFIG 4ª vaga (outras) | ver `CONFIG_CANDIDATOS_EXTRA.md` | não | propostas complementares — **escolher 1** |

## Tabela dos labs (CVE + CONFIG)

| # | ID | Tipo | Pacote / superfície | Resultado / status | Vulnerable → corrigido (ou inseguro → seguro) | Fontes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | CVE-2024-38428 | **CVE** | `wget` | **EXECUTADO — SUCESSO** | `1.21.4-1ubuntu4` → `≥ 1.21.4-1ubuntu4.1` | [CVE](https://ubuntu.com/security/CVE-2024-38428), [USN-6852-1](https://ubuntu.com/security/notices/USN-6852-1) |
| 2 | CVE-2024-32487 | **CVE** | `less` | **EXECUTADO — FALHA** | `590-2ubuntu2` → `≥ 590-2ubuntu2.1` | [CVE](https://ubuntu.com/security/CVE-2024-32487), [USN-6756-1](https://ubuntu.com/security/notices/USN-6756-1) |
| 3 | CONFIG-SSH-PERMIT-ROOT | **CONFIG** | `sshd` `PermitRootLogin` | **SELECIONADA** (pendente prep.) | `PermitRootLogin yes` → `prohibit-password` (ou `no`) | CIS / hardening SSH; **não é CVE** |
| 4 | CONFIG-NGINX-AUTOINDEX | **CONFIG** | `nginx` `autoindex` | **SELECIONADA** (pendente prep.) | `autoindex on` → `off` | hardening web; **não é CVE** |
| 5 | CONFIG-FAIL2BAN-ABSENT | **CONFIG** | `fail2ban` serviço | **SELECIONADA** (pendente prep.) | inactive/disabled → `enable --now` | defesa em profundidade; **não é CVE** |
| 6 | *(1 CONFIG a escolher)* | **CONFIG** | ver 4ª vaga | **AGUARDANDO ESCOLHA** | config Bash / permissões / rede / higiene | **não é CVE** |
| 7 | CVE-2024-6387 | **CVE** | `openssh-server` | **SELECIONADA** (pendente prep.) | ex. `1:9.6p1-3ubuntu13` → `≥ 1:9.6p1-3ubuntu13.3` | [CVE](https://ubuntu.com/security/CVE-2024-6387), [USN-6859-1](https://ubuntu.com/security/notices/USN-6859-1) |
| 8 | CVE-2024-48990 | **CVE** | `needrestart` | **SELECIONADA** (pendente prep.) | ex. `3.6-7ubuntu4` → `≥ 3.6-7ubuntu4.3` | [CVE](https://ubuntu.com/security/CVE-2024-48990), [USN-7117-1](https://ubuntu.com/security/notices/USN-7117-1) |
| 9 | CVE-2023-4911 | **CVE** | `libc6` / glibc | **SELECIONADA** (pendente prep.) | **jammy:** ex. `2.35-0ubuntu3.3` → `≥ 2.35-0ubuntu3.4`; **noble** já Fixed em `2.38-1ubuntu6` (release) | [CVE](https://ubuntu.com/security/CVE-2023-4911), [USN-6409-1](https://ubuntu.com/security/notices/USN-6409-1) |
| 10 | CVE-2024-12084 | **CVE** | `rsync` | **SELECIONADA** (pendente prep.) | `3.2.7-1ubuntu1` → `≥ 3.2.7-1ubuntu1.1` | [CVE](https://ubuntu.com/security/CVE-2024-12084), [USN-7206-1](https://ubuntu.com/security/notices/USN-7206-1) |
| 11 | CVE-2025-48384 | **CVE** | `git` | **SELECIONADA** (pendente prep.) | `1:2.43.0-1ubuntu7.2` → `≥ 1:2.43.0-1ubuntu7.3` | [CVE](https://ubuntu.com/security/CVE-2025-48384), [USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1) |
| 12 | CVE-2024-11053 | **CVE** | `curl` / `libcurl4t64` | **SELECIONADA** (pendente prep.) | `8.5.0-2ubuntu10.5` → `≥ 8.5.0-2ubuntu10.6` | [CVE](https://ubuntu.com/security/CVE-2024-11053), [USN-7162-1](https://ubuntu.com/security/notices/USN-7162-1) |

Versões CVE conferidas nas páginas oficiais da Canonical (CVE Tracker + USN / Launchpad) em 21/11/2026. **Não inventadas.**

### Notas de fit (CVE novas / promovidas)

| CVE | Fit / observação para o lab |
| --- | --- |
| CVE-2024-6387 (regreSSHion) | Fit **Alto** em 24.04: remediação `apt` + verificação por versão; **sem** PoC. Nota Canonical: quirk de socket activation no noble pode mudar explotabilidade — o lab **não** testa explotabilidade. |
| CVE-2024-48990 (needrestart) | Fit **Alto** em Server 24.04; pacote padrão; só versão. |
| CVE-2023-4911 (Looney Tunables) | Fit **Alto** em **22.04**; em **24.04** o tracker marca Fixed na linha de release — lab vulnerável histórico tende a usar **jammy** (ou documentar limitação). Reboot após update. |
| CVE-2024-12084 (rsync) | Fit **Alto**; lab só por versão — **sem** daemon / porta 873. |
| CVE-2025-48384 (git) / CVE-2024-11053 (curl) | Já tinham fichas; mantidas na seleção. |

### CONFIG: trio selecionado vs. 4ª vaga

| ID | Status | Papel |
| --- | --- | --- |
| CONFIG-SSH-PERMIT-ROOT | **SELECIONADA** | 1/4 — autenticação SSH (root) |
| CONFIG-NGINX-AUTOINDEX | **SELECIONADA** | 2/4 — endurecimento de serviço web |
| CONFIG-FAIL2BAN-ABSENT | **SELECIONADA** | 3/4 — presença/estado de defesa |
| *(1 a escolher)* | **AGUARDANDO** | 4/4 — ver [`CONFIG_CANDIDATOS_EXTRA.md`](CONFIG_CANDIDATOS_EXTRA.md) |

**Cobertura do trio:** acesso SSH permissivo + exposição de listagem HTTP + ferramenta de ban desligada. A 4ª vaga deve **complementar** (privilégios, segredos/perms, rede, higiene de pacotes, logging/audit distinto de fail2ban) — **evitar** outro gémeo puro de autenticação SSH.

## Por que CONFIG ≠ CVE

Cada caso CONFIG muda **configuração / permissões / bind / política**, verificável por inspeção (`sshd -T`, `stat`, `ss`, `ufw status`, `sudo -l`, etc.), remediável por Bash **sem** depender de `.deb` vulnerável, e rotulado **CONFIG** para não misturar com remediação por atualização de pacote.

## Ordem recomendada (após aprovação da 4ª CONFIG + autorização)

1. **CONFIG-SSH-PERMIT-ROOT** — já selecionada; barata (drop-in sshd).  
2. **CONFIG-NGINX-AUTOINDEX** / **CONFIG-FAIL2BAN-ABSENT** — selecionadas; pacotes de lab + conf/serviço.  
3. **4ª CONFIG escolhida** — da lista complementar.  
4. **CVE-2024-11053 (`curl`)** — similar ao wget.  
5. **CVE-2024-6387 (`openssh`)** / **CVE-2024-48990 (`needrestart`)** — High, apt + versão.  
6. **CVE-2024-12084 (`rsync`)** / **CVE-2025-48384 (`git`)**.  
7. **CVE-2023-4911 (`glibc`)** — preferir jammy; reboot.

Labs 1–2 (wget / less) já fechados; não precisam reexecução salvo pedido explícito.

## Gates obrigatórios

- Aguardar aprovação da **1 CONFIG** restante e autorização antes de preparar ambiente vulnerável.  
- Sem inventar CVE/versão.  
- Sem `terraform apply` / recursos pagos AWS sem `AUTORIZO_RECURSOS_PAGOS`.  
- Casos CONFIG claramente distintos de CVE.  
- Remediação e verificação **independentes** do modelo.  
- Sem exploração ativa / PoC ofensiva.  
- EC2 privada; Ubuntu 24.04 preferido (exceto nota jammy para glibc).

## Próximo passo

1. CVE (8) e CONFIG (3/4) já refletidas acima.  
2. **Escolher 1 CONFIG** em `CONFIG_CANDIDATOS_EXTRA.md` (secção 4ª vaga).  
3. Só então: stubs prepare/verify → eventual provisionamento.
