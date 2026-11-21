# Portfólio de 10 laboratórios — proposta para aprovação

**Status geral:** 2 labs **executados**; 8 labs **pendentes de aprovação** (não preparar AMI / não gerar script / não `terraform apply` até autorização explícita).  
**Modelo oficial previsto (quando houver geração):** `OPENAI_MODEL` (mesmo modelo dos experimentos oficiais).   <!-- pragma: allowlist secret -->
**SO alvo:** Ubuntu 24.04 LTS (`noble`), EC2 privada, sem exploração ativa.  
**Data da proposta:** 21 de novembro de 2026.

Este documento é a ficha de portfólio. Detalhes por lab estão em `scenarios/<id>/scenario.md`. Analogias para leitores não técnicos (problema / exemplo / correção): [`DESCRICOES_NAOTECNICAS.md`](DESCRICOES_NAOTECNICAS.md). O inventário histórico de candidatos CVE permanece em [`README.md`](README.md). Pesquisa de CVEs de **alto impacto** (2021–2026) vs. fit do lab: [`CANDIDATOS_ALTO_IMPACTO.md`](CANDIDATOS_ALTO_IMPACTO.md).

## Inventário pré-proposta

| ID | `scenario.md` | Artefatos prepare/verify | Execução real |
| --- | --- | --- | --- |
| CVE-2024-38428 (`wget`) | sim | sim | **SUCESSO** (`results/`, `docs/resultados_tcc.md`, reexecução) |
| CVE-2024-32487 (`less`) | sim | sim | **FALHA** (`docs/resultado_cve_2024_32487.md`, `results/reexecution/CVE-2024-32487/`) |
| CVE-2024-11053 (`curl`) | sim | não | não |
| CVE-2024-5742 (`nano`) | sim | não | não |
| CVE-2025-1372 (`elfutils`) | sim | não | não |
| CVE-2025-48384 (`git`) | sim | não | não |
| CVE-2025-0840 (`binutils`) | sim | não | não (reserva) |
| CVE-2025-64505 (`libpng`) | sim | não | não (reserva) |
| CVE-2025-45582 (`tar`) | sim | não | não (reserva) |
| CVE-2024-12084 (`rsync`) | sim | não | não (reserva) |
| CONFIG-* | **novos nesta proposta** | stubs só | não |

## Tabela dos 10 labs

| # | ID | Tipo | Pacote / superfície | Resultado / status | Vulnerable → corrigido (ou estado inseguro → seguro) | Fontes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | CVE-2024-38428 | **CVE** | `wget` | **EXECUTADO — SUCESSO** | `1.21.4-1ubuntu4` → `≥ 1.21.4-1ubuntu4.1` | [CVE](https://ubuntu.com/security/CVE-2024-38428), [USN-6852-1](https://ubuntu.com/security/notices/USN-6852-1) |
| 2 | CVE-2024-32487 | **CVE** | `less` | **EXECUTADO — FALHA** | `590-2ubuntu2` → `≥ 590-2ubuntu2.1` | [CVE](https://ubuntu.com/security/CVE-2024-32487), [USN-6756-1](https://ubuntu.com/security/notices/USN-6756-1) |
| 3 | CONFIG-SSH-PERMIT-ROOT | **CONFIG** | `sshd` `PermitRootLogin` | **PENDENTE APROVAÇÃO** | `PermitRootLogin yes` → `prohibit-password` (ou `no`) | CIS / hardening SSH; **não é CVE** |
| 4 | CONFIG-WORLD-WRITABLE-SENSITIVE | **CONFIG** | arquivo sensível de lab | **PENDENTE APROVAÇÃO** | modo `0666` → `0600` root:root | permissões POSIX; **não é CVE** |
| 5 | CONFIG-CRON-WEAK-PERMS | **CONFIG** | `/etc/cron.d` job | **PENDENTE APROVAÇÃO** | job `0666` → `0644` root:root | cron + permissões; **não é CVE** |
| 6 | CONFIG-LOCAL-HTTP-BIND | **CONFIG** | serviço HTTP de lab | **PENDENTE APROVAÇÃO** | bind `0.0.0.0:18080` → `127.0.0.1:18080` (ou parado) | superfície local; **não é CVE** |
| 7 | CVE-2024-11053 | **CVE** | `curl` / `libcurl4t64` | **PENDENTE APROVAÇÃO** | `8.5.0-2ubuntu10.5` → `≥ 8.5.0-2ubuntu10.6` | [CVE](https://ubuntu.com/security/CVE-2024-11053), [USN-7162-1](https://ubuntu.com/security/notices/USN-7162-1) |
| 8 | CVE-2024-5742 | **CVE** | `nano` | **PENDENTE APROVAÇÃO** | `7.2-2build1` → `≥ 7.2-2ubuntu0.1` | [CVE](https://ubuntu.com/security/CVE-2024-5742), [USN-7064-1](https://ubuntu.com/security/notices/USN-7064-1) |
| 9 | CVE-2025-1372 | **CVE** | `elfutils` | **PENDENTE APROVAÇÃO** | `0.190-1.1build4.1` → `≥ 0.190-1.1ubuntu0.1` | [CVE](https://ubuntu.com/security/CVE-2025-1372), [USN-7369-1](https://ubuntu.com/security/notices/USN-7369-1) |
| 10 | CVE-2025-48384 | **CVE** | `git` | **PENDENTE APROVAÇÃO** | `1:2.43.0-1ubuntu7.2` → `≥ 1:2.43.0-1ubuntu7.3` | [CVE](https://ubuntu.com/security/CVE-2025-48384), [USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1) |

Versões CVE acima foram conferidas nas páginas oficiais da Canonical (CVE Tracker + USN) em 21/11/2026. **Não inventadas.**

## Por que estes 4 CONFIG (e não CVEs)

Cada caso muda **configuração / permissões / bind**, verificável por inspeção (`sshd -T`, `stat`, `ss`/`ss -ltn`), remediável sem `apt` de pacote vulnerável e claramente rotulado **CONFIG** para não misturar com remediação por atualização de pacote.

## Por que estes 4 CVEs adicionais

| CVE | Motivo de prioridade no portfólio |
| --- | --- |
| curl | Reprodutibilidade **fácil**; cliente de rede; alinhado ao padrão wget |
| nano | Reprodutibilidade **fácil**; pacote único |
| elfutils | Reprodutibilidade **fácil**; utilitário local; USN recente |
| git | Prioridade Ubuntu **high** (KEV); diversifica VCS; remediação ainda por versão |

Reservas (fora dos 10, se algum CVE for rejeitado): `binutils`, `libpng`, `tar`, `rsync` — já com fichas em `scenarios/`.

## Ordem recomendada de execução (após aprovação)

1. **CONFIG-SSH-PERMIT-ROOT** — preparação barata (só drop-in sshd); valida o pipeline CONFIG sem `.deb` histórico.  
2. **CONFIG-WORLD-WRITABLE-SENSITIVE** — ainda mais simples (um arquivo).  
3. **CONFIG-CRON-WEAK-PERMS** — permissões + cron.  
4. **CONFIG-LOCAL-HTTP-BIND** — serviço local controlado (sem IP público / SG sem entrada).  
5. **CVE-2024-11053 (`curl`)** — CVE “fácil”, similar ao wget.  
6. **CVE-2024-5742 (`nano`)** — CVE fácil, pacote único.  
7. **CVE-2025-1372 (`elfutils`)** — CVE fácil, outro utilitário.  
8. **CVE-2025-48384 (`git`)** — CVE de maior complexidade relativa / severidade.

Os labs 1–2 já estão fechados (sucesso / falha) e não precisam reexecução para completar o portfólio de 10, salvo se o usuário pedir repetição.

## Gates obrigatórios (master prompt)

- Apresentar candidatos e **aguardar aprovação** antes de preparar ambiente vulnerável.  
- Sem inventar CVE/versão.  
- Sem `terraform apply` / recursos pagos AWS sem `AUTORIZO_RECURSOS_PAGOS`.  
- Casos CONFIG claramente distintos de CVE.  
- Remediação e verificação **independentes** do modelo.  
- Sem exploração ativa / PoC ofensiva.  
- EC2 privada; Ubuntu 24.04 preferido.

## Próximo passo

**Aprovar** quais dos 8 pendentes entram na implementação (prepare/verify scripts + eventual provisionamento). Até lá: só documentação / stubs.
