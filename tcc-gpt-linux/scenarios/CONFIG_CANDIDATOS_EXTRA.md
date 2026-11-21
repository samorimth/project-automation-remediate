# CONFIG — quarteto selecionado + histórico de candidatos

**Tipo:** todos são **CONFIG** (configuração / permissão / política de SO). **Não são CVE.**  
**SO alvo:** Ubuntu 24.04 LTS, EC2 **privada**, remediação por Bash, verificação independente, **sem** PoC de exploração.  
**Contexto:** **4/4 CONFIG selecionadas e aprovadas** — bloco completo.

Nenhum ambiente foi preparado. Aguardar autorização explícita antes de AMI / GPT / `terraform apply`.

---

## Quarteto selecionado / aprovado (4/4)

| # | ID | Tema | Status |
| --- | --- | --- | --- |
| 1 | CONFIG-SSH-PERMIT-ROOT | SSH `PermitRootLogin yes` | **SELECIONADA / APROVADA** |
| 2 | CONFIG-NGINX-AUTOINDEX | nginx `autoindex on` (listagem HTTP) | **SELECIONADA / APROVADA** |
| 3 | CONFIG-FAIL2BAN-ABSENT | fail2ban parado/desabilitado | **SELECIONADA / APROVADA** |
| 4 | CONFIG-SUDOERS-NOPASSWD | privilégios (`sudo` sem senha / `NOPASSWD`) | **SELECIONADA / APROVADA** |

Fichas: `scenarios/CONFIG-SSH-PERMIT-ROOT/`, `CONFIG-NGINX-AUTOINDEX/`, `CONFIG-FAIL2BAN-ABSENT/`, `CONFIG-SUDOERS-NOPASSWD/`.

**Cobertura do quarteto:** autenticação SSH permissiva (root) · endurecimento de serviço web (vitrine de ficheiros) · estado de ferramenta de defesa (ban) · privilégios locais (`NOPASSWD`).

---

## 4ª vaga — decisão (fechada)

| ID | Tema | Correção típica | Verify (ideia) | Decisão |
| --- | --- | --- | --- | --- |
| **CONFIG-SUDOERS-NOPASSWD** | privilégios (`sudo` sem senha) | remover `NOPASSWD` | `sudo -n -l -U` | **APROVADA (4/4)** |
| CONFIG-WORLD-WRITABLE-SENSITIVE | segredo world-writable | `chmod 0600` | `stat` | reserva (não escolhida) |
| CONFIG-UFW-DISABLED | firewall host inativo | `ufw enable` + regras | `ufw status` | reserva (não escolhida) |
| CONFIG-UNATTENDED-UPGRADES-OFF | higiene de updates desligada | reativar `unattended-upgrades` | `systemctl` + conf | reserva |
| CONFIG-LOCAL-HTTP-BIND | serviço em `0.0.0.0` | bind `127.0.0.1` | `ss`/`curl` | reserva |
| CONFIG-PRIVATE-KEY-0644 | chave privada `0644` | `chmod 600` | `stat -c '%a'` | reserva |
| CONFIG-CRON-WEAK-PERMS | cron world-writable | `0644` `root:root` | `stat` | reserva |
| CONFIG-AUDITD-INACTIVE | auditd parado | `enable --now auditd` | `systemctl is-active` | reserva |

*(Omitidos de propósito: `CONFIG-SSH-PASSWORD-AUTH` / gémeos SSH de auth — sobrepõem demais o slot 1.)*

---

## Detalhe da 4ª aprovada: CONFIG-SUDOERS-NOPASSWD

**Problema.** Um usuário de lab tem `NOPASSWD: ALL` (ou amplo) em `/etc/sudoers.d/`, podendo virar root sem digitar senha. **CONFIG** clássica de hardening — **não é CVE**.

**Exemplo não técnico.** O estagiário ganha um crachá de “síndico permanente” que abre qualquer sala sem pedir confirmação. Basta alguém usar o crachá (ou a sessão do estagiário) e o prédio inteiro fica acessível.

**Correção.** Remover o drop-in `NOPASSWD` ou restringir a comandos mínimos **com** senha; `chmod 0440` no arquivo; validar com `visudo -c`.

**Verify.**  
- Antes: `sudo -n -l -U <user>` lista comandos sem pedir senha / mostra `NOPASSWD`.  
- Depois: `sudo -n true` falha para esse usuário (ou lista sem `NOPASSWD`).

**Fit.** Alto — padrão CIS; inspeção clara; EC2 privada.

**Por que complementa o trio.** Privileges locais; não toca SSH root, nginx nem fail2ban.

Ficha completa: [`CONFIG-SUDOERS-NOPASSWD/scenario.md`](CONFIG-SUDOERS-NOPASSWD/scenario.md).

---

## Histórico — outros candidatos (reserva)

### CONFIG-WORLD-WRITABLE-SENSITIVE

**Problema.** Arquivo sensível sintético (`/etc/tcc-lab/secret.env`) com modo `0666`. **CONFIG** de permissão POSIX — não é CVE.  
**Correção.** `chown root:root` + `chmod 0600`. Stub: `CONFIG-WORLD-WRITABLE-SENSITIVE/scenario.md`.

### CONFIG-UFW-DISABLED

**Problema.** Firewall do host (`ufw`) **inativo**. **CONFIG**.  
**Correção.** `ufw default deny incoming` + regras mínimas + `ufw --force enable`.

### CONFIG-UNATTENDED-UPGRADES-OFF

**Problema.** `unattended-upgrades` desabilitado / conf off. **CONFIG** de higiene de updates.  
**Correção.** Reativar serviço + conf `APT::Periodic::Unattended-Upgrade "1"`.

### CONFIG-LOCAL-HTTP-BIND

**Problema.** Serviço HTTP de lab escuta em `0.0.0.0`. **CONFIG** de exposição.  
**Correção.** Bind `127.0.0.1`. Stub: `CONFIG-LOCAL-HTTP-BIND/scenario.md`.

### CONFIG-PRIVATE-KEY-0644

**Problema.** Chave privada de lab com modo `0644`. **CONFIG**.  
**Correção.** `chmod 600` (+ dir `~/.ssh` `700`).

### CONFIG-CRON-WEAK-PERMS

**Problema.** Job em `/etc/cron.d/` world-writable. **CONFIG**.  
**Correção.** Job `0644` `root:root`. Stub: `CONFIG-CRON-WEAK-PERMS/scenario.md`.

### CONFIG-AUDITD-INACTIVE

**Problema.** `auditd` parado/desabilitado. **CONFIG** de logging (≠ fail2ban).  
**Correção.** `systemctl enable --now auditd`.

---

## Alternativas documentadas (fora da seleção)

| ID | Nota |
| --- | --- |
| CONFIG-SSH-PASSWORD-AUTH | Gémeo forte de auth SSH com o slot 1 — evitar |
| CONFIG-SSH-EMPTY-PASSPHRASE-KEY | Credencial SSH; overlap temático com slot 1 |
| CONFIG-SUDOERS-UNRESTRICTED | Próximo de NOPASSWD; o slot 4 já fechou com NOPASSWD |
| CONFIG-BASHRC-PATH-HIJACK | Bom pedagogicamente; reserva |
| CONFIG-SYSCTL-IP-FORWARD | Válido; menos “clássico” que ufw/sudoers |

---

## Próximo passo

Seleção CONFIG **fechada (4/4)**. Aguardar autorização para implementação (prepare/verify → eventual provisionamento).  
Até lá: só documentação — **sem** AMI / GPT / `terraform apply`.
