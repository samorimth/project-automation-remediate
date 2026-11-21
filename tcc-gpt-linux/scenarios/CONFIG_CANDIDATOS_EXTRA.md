# CONFIG — trio selecionado + candidatos para a 4ª vaga

**Tipo:** todos são **CONFIG** (configuração / permissão / política de SO). **Não são CVE.**  
**SO alvo:** Ubuntu 24.04 LTS, EC2 **privada**, remediação por Bash, verificação independente, **sem** PoC de exploração.  
**Contexto:** **3 CONFIG selecionadas** — falta **1** para completar o bloco de 4.

Nenhum ambiente foi preparado. Após a escolha do usuário, criar/ajustar `scenarios/<id>/scenario.md` + prepare/verify.

---

## Trio já selecionado (3/4)

| # | ID | Tema | Status |
| --- | --- | --- | --- |
| 1 | CONFIG-SSH-PERMIT-ROOT | SSH `PermitRootLogin yes` | **SELECIONADA** |
| 2 | CONFIG-NGINX-AUTOINDEX | nginx `autoindex on` (listagem HTTP) | **SELECIONADA** |
| 3 | CONFIG-FAIL2BAN-ABSENT | fail2ban parado/desabilitado | **SELECIONADA** |

Fichas: `scenarios/CONFIG-SSH-PERMIT-ROOT/`, `CONFIG-NGINX-AUTOINDEX/`, `CONFIG-FAIL2BAN-ABSENT/`.

**O que o trio já cobre:** autenticação SSH permissiva (root) · endurecimento de serviço web (vitrine de ficheiros) · estado de ferramenta de defesa (ban).  
**O que a 4ª deve acrescentar:** privilégios locais, segredos/perms, exposição de rede/firewall, higiene de updates, ou logging/audit **distinto** de fail2ban — **sem** outro gémeo puro de auth SSH.

---

## 4ª vaga — tabela rápida (8 propostas complementares)

| ID | Tema | Correção típica | Verify (ideia) | Fit | Por que complementa o trio |
| --- | --- | --- | --- | --- | --- |
| CONFIG-SUDOERS-NOPASSWD | privilégios (`sudo` sem senha) | remover `NOPASSWD` | `sudo -n -l -U` | Alto | Privileges — não coberto pelo trio |
| CONFIG-WORLD-WRITABLE-SENSITIVE | segredo world-writable | `chmod 0600` | `stat` | Alto | Secrets/perms — distinto de nginx/SSH |
| CONFIG-UFW-DISABLED | firewall host inativo | `ufw enable` + regras | `ufw status` | Alto | Rede/host — SG ≠ ufw; ≠ fail2ban |
| CONFIG-UNATTENDED-UPGRADES-OFF | higiene de updates desligada | reativar `unattended-upgrades` | `systemctl` + conf | Alto | Pacotes/updates — eixo novo |
| CONFIG-LOCAL-HTTP-BIND | serviço em `0.0.0.0` | bind `127.0.0.1` | `ss`/`curl` | Alto | Exposição de rede — ≠ autoindex |
| CONFIG-PRIVATE-KEY-0644 | chave privada `0644` | `chmod 600` | `stat -c '%a'` | Alto | Segredo em disco — ≠ PermitRootLogin |
| CONFIG-CRON-WEAK-PERMS | cron world-writable | `0644` `root:root` | `stat` | Alto | Persistência/agendamento — eixo novo |
| CONFIG-AUDITD-INACTIVE | auditd parado | `enable --now auditd` | `systemctl is-active` | Médio-Alto | Logging/audit trail ≠ fail2ban (ban) |

*(Omitidos de propósito como 4ª vaga: `CONFIG-SSH-PASSWORD-AUTH` / gémeos SSH de auth — sobrepõem demais o slot 1.)*

---

## Recomendação (top 3 para a 4ª vaga)

1. **CONFIG-SUDOERS-NOPASSWD** — melhor equilíbrio pedagógico: privilégios locais clássicos CIS, verify claro, zero overlap com nginx/fail2ban/SSH-root.  
2. **CONFIG-WORLD-WRITABLE-SENSITIVE** — eixo “segredos em disco”; stub já existe; muito barato no pipeline.  
3. **CONFIG-UFW-DISABLED** — defesa em profundidade de **rede** (complementa fail2ban, que é reação a tentativas, não filtragem de portas).

---

## Detalhes por candidato (4ª vaga)

### 1. CONFIG-SUDOERS-NOPASSWD

**Problema.** Um usuário de lab tem `NOPASSWD: ALL` (ou amplo) em `/etc/sudoers.d/`, podendo virar root sem digitar senha. **CONFIG** clássica de hardening.

**Exemplo não técnico.** O estagiário ganha um crachá de “síndico permanente” que abre qualquer sala sem pedir confirmação. Basta alguém usar o crachá (ou a sessão do estagiário) e o prédio inteiro fica acessível.

**Correção.** Remover o drop-in `NOPASSWD` ou restringir a comandos mínimos **com** senha; `chmod 0440` no arquivo; validar com `visudo -c`.

**Verify.**  
- Antes: `sudo -n -l -U <user>` lista comandos sem pedir senha / mostra `NOPASSWD`.  
- Depois: `sudo -n true` falha para esse usuário (ou lista sem `NOPASSWD`).

**Fit.** Alto — padrão CIS; inspeção clara; EC2 privada.

**Por que complementa o trio.** Privileges locais; não toca SSH root, nginx nem fail2ban.

---

### 2. CONFIG-WORLD-WRITABLE-SENSITIVE

**Problema.** Arquivo sensível sintético (`/etc/tcc-lab/secret.env`) com modo `0666` (qualquer usuário local escreve). **CONFIG** de permissão POSIX — não é CVE.

**Exemplo não técnico.** Caderno com a senha do Wi‑Fi aberto na mesa da sala de espera, com caneta ao lado: qualquer visitante lê **e** troca o que está escrito.

**Correção.** `chown root:root` + `chmod 0600` no ficheiro de lab.

**Verify.**  
- Antes: `stat -c '%a'` → `666`.  
- Depois: → `600` (sem bit de escrita para other).

**Fit.** Alto — stub já em `CONFIG-WORLD-WRITABLE-SENSITIVE/scenario.md`.

**Por que complementa o trio.** Secrets/perms em disco; eixo diferente de serviço web e de auth SSH.

---

### 3. CONFIG-UFW-DISABLED

**Problema.** O firewall do host (`ufw`) está **inativo**. Em EC2 o Security Group já filtra, mas o lab ensina defesa em profundidade. **CONFIG**.

**Exemplo não técnico.** O condomínio tem portaria na rua (Security Group), mas as portas internas dos apartamentos estão todas destrancadas (ufw off). Se alguém já estiver no corredor, nada impede ir de porta em porta.

**Correção.** `ufw default deny incoming`, permitir só o necessário (ex. SSH da rede privada), `ufw --force enable`.

**Verify.**  
- Antes: `ufw status` → `inactive`.  
- Depois: `ufw status` → `active` (+ regra SSH presente).

**Fit.** Alto — comando Bash simples; verificável; sem PoC de scan.

**Por que complementa o trio.** Rede/host firewall ≠ fail2ban (ban após tentativas) ≠ listagem nginx ≠ PermitRootLogin.

---

### 4. CONFIG-UNATTENDED-UPGRADES-OFF

**Problema.** `unattended-upgrades` desabilitado / conf de lab com atualizações automáticas de segurança **off**, deixando o host sem higiene contínua de patches. **CONFIG** de política de updates (não é “corrigir um CVE específico”).

**Exemplo não técnico.** A assinatura da revista de recalls de segurança foi cancelada: o prédio deixa de receber avisos e peças de reposição sozinho. Cada falha nova fica sem remendo até alguém lembrar de ir à loja.

**Correção.** Reativar pacote/serviço `unattended-upgrades` e conf mínima (`APT::Periodic::Unattended-Upgrade "1"`); `systemctl enable --now unattended-upgrades` (ou equivalente documentado).

**Verify.**  
- Antes: serviço inactive **ou** conf com Unattended-Upgrade `"0"` / pacote removido.  
- Depois: conf `"1"` + serviço enabled/active (critério documentado).

**Fit.** Alto — eixo “higiene de pacotes”; alinhado ao discurso CVE-vs-CONFIG do TCC.

**Por que complementa o trio.** Update hygiene — nenhum dos três slots cobre manutenção contínua.

---

### 5. CONFIG-LOCAL-HTTP-BIND

**Problema.** Serviço HTTP de lab escuta em `0.0.0.0` em vez de só `127.0.0.1`. **CONFIG** de exposição de rede.

**Exemplo não técnico.** Interfone que atende também a rua e o prédio vizinho, não só a portaria.

**Correção.** Bind em `127.0.0.1` ou desligar o serviço.

**Verify.**  
- Antes: `ss -lntp` mostra listen em `*:PORT` / `0.0.0.0:PORT`.  
- Depois: só `127.0.0.1:PORT` (ou serviço parado).

**Fit.** Alto — stub já existe; distinto de autoindex (aqui o problema é **onde** escuta, não a listagem).

**Por que complementa o trio.** Network exposure; mesmo se usar HTTP, o eixo é bind, não `autoindex`.

---

### 6. CONFIG-PRIVATE-KEY-0644

**Problema.** Chave privada SSH (ou TLS de lab) com modo `0644` (legível por outros usuários locais). **CONFIG** de permissão.

**Exemplo não técnico.** A chave do carro fica no porta-luvas **destrancado** e com o vidro aberto: qualquer passageiro do banco de trás pode pegar.

**Correção.** `chmod 600` (e `chown` do dono); dir `~/.ssh` com `700`.

**Verify.**  
- Antes: `stat -c '%a' /path/to/id_lab` → `644`.  
- Depois: → `600`.

**Fit.** Alto — mínimo; cuidado: não versionar chave real.

**Por que complementa o trio.** Credencial em ficheiro (perms), não política `PermitRootLogin`.

---

### 7. CONFIG-CRON-WEAK-PERMS

**Problema.** Job em `/etc/cron.d/` (ou script chamado pelo cron) com permissão de escrita para todos. **CONFIG**.

**Exemplo não técnico.** Agenda da empresa no mural do corredor, com caneta livre: um estranho risca “pagar as contas” e escreve outra ordem.

**Correção.** Job `0644` `root:root` (script associado sem write para other).

**Verify.**  
- Antes: `stat` mostra world-writable.  
- Depois: `0644` `root:root`.

**Fit.** Alto — stub já existe; eixo persistência/agendamento.

**Por que complementa o trio.** Scheduling/perms — fora de SSH, nginx e fail2ban.

---

### 8. CONFIG-AUDITD-INACTIVE

**Problema.** `auditd` instalado mas **parado/desabilitado**, sem trilha de auditoria local. **CONFIG** de logging/monitoramento (eixo distinto de fail2ban).

**Exemplo não técnico.** As câmeras do corredor existem, mas o gravador está desligado: ninguém é barrado na porta (isso seria o porteiro/fail2ban), mas também **não fica registo** de quem passou.

**Correção.** `apt-get install -y auditd` (se ausente) + `systemctl enable --now auditd`.

**Verify.**  
- Antes: `systemctl is-active auditd` → `inactive`.  
- Depois: → `active` (+ `is-enabled`).

**Fit.** Médio-Alto — parecido na forma com fail2ban (estado de serviço), mas o **papel** é audit trail, não ban. Usar só se quiser contraste explícito “deteção/registo vs. reação”.

**Por que complementa o trio.** Logging/audit ≠ fail2ban (reação) ≠ nginx ≠ SSH root. Preferir se a banca valorizar monitoramento; senão, privilégios/segredos/ufw são mais ortogonais.

---

## Alternativas já documentadas (fora do top da 4ª vaga)

Ainda elegíveis, mas **não** recomendadas agora por overlap ou prioridade menor:

| ID | Nota |
| --- | --- |
| CONFIG-SSH-PASSWORD-AUTH | Gémeo forte de auth SSH com o slot 1 — evitar como 4ª |
| CONFIG-SSH-EMPTY-PASSPHRASE-KEY | Credencial SSH; overlap temático com slot 1 |
| CONFIG-SUDOERS-UNRESTRICTED | Próximo de NOPASSWD; escolher **um** dos dois |
| CONFIG-BASHRC-PATH-HIJACK | Bom pedagogicamente; um pouco mais abstracto |
| CONFIG-SYSCTL-IP-FORWARD | Válido; menos “clássico” que ufw/sudoers |

---

## Como escolher a 4ª

Responder com **1 ID**. Sugestão: começar pelo top 3 acima.

Até lá: só documentação — **sem** AMI / GPT / `terraform apply`.
