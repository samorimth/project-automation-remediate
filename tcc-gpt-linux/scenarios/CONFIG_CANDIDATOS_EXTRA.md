# Candidatos CONFIG extras — escolher 3 para completar o bloco de 4

**Tipo:** todos são **CONFIG** (configuração / permissão / política de SO). **Não são CVE.**  
**SO alvo:** Ubuntu 24.04 LTS, EC2 **privada**, remediação por Bash, verificação independente, **sem** PoC de exploração.  
**Contexto:** 1 CONFIG já **selecionada** — `CONFIG-SSH-PERMIT-ROOT`. Faltam **3**.  
**Opcionais já propostas (também elegíveis):** `CONFIG-WORLD-WRITABLE-SENSITIVE`, `CONFIG-CRON-WEAK-PERMS`, `CONFIG-LOCAL-HTTP-BIND` (ver `PORTFOLIO_10_LABS.md`).

Nenhum ambiente foi preparado. Após a escolha do usuário, criar `scenarios/<id>/scenario.md` + prepare/verify.

---

## Tabela rápida (novas propostas)

| ID | Tema | Correção típica | Verify (ideia) | Fit |
| --- | --- | --- | --- | --- |
| CONFIG-SSH-PASSWORD-AUTH | SSH com senha habilitada | `PasswordAuthentication no` | `sshd -T` | Alto |
| CONFIG-SSH-EMPTY-PASSPHRASE-KEY | Chave SSH lab sem passphrase | regenerar com passphrase / remover | `ssh-keygen -y` + teste passphrase | Alto |
| CONFIG-UFW-DISABLED | Firewall ufw inativo | `ufw enable` + regras mínimas | `ufw status` | Alto |
| CONFIG-SUDOERS-NOPASSWD | sudo sem senha para usuário lab | remover `NOPASSWD` | `sudo -l -U` | Alto |
| CONFIG-SUDOERS-UNRESTRICTED | sudoers amplo (`ALL=(ALL) ALL` + write fraco) | restringir comando + `0440` | `stat` + `visudo -c` / `sudo -l` | Alto |
| CONFIG-PRIVATE-KEY-0644 | chave privada `0644` | `chmod 600` | `stat -c '%a'` | Alto |
| CONFIG-BASHRC-PATH-HIJACK | `PATH` inseguro no `.bashrc` | PATH só com dirs confiáveis | `grep`/inspecionar PATH efetivo | Alto |
| CONFIG-SYSCTL-IP-FORWARD | `ip_forward=1` sem necessidade | `sysctl` → `0` | `sysctl net.ipv4.ip_forward` | Médio-Alto |
| CONFIG-NGINX-AUTOINDEX | listagem de diretório HTTP | `autoindex off` | curl local / conf | Médio-Alto |
| CONFIG-FAIL2BAN-ABSENT | fail2ban instalado mas parado | `systemctl enable --now` | `systemctl is-active` | Médio |

*(Docker socket root-equivalente: **omitido** de propósito — pesado demais para o lab atual.)*

---

## Detalhes por candidato

### 1. CONFIG-SSH-PASSWORD-AUTH

**Problema.** O servidor SSH aceita autenticação por senha (`PasswordAuthentication yes`). Em EC2/cloud o padrão saudável é só chave; senha abre força bruta e vazamento de credencial. **CONFIG**, não CVE.

**Exemplo não técnico.** É como o prédio ter fechadura de senha numérica na portaria, além da biometria dos moradores: qualquer um que descubra ou chute o código entra. Melhor deixar só o cartão (chave) autorizado.

**Correção.** Drop-in sshd com `PasswordAuthentication no` (e, se aplicável, `KbdInteractiveAuthentication no`); `systemctl reload ssh`.

**Verify.**  
- Antes: `sshd -T | awk '/^passwordauthentication /{print $2}'` → `yes`.  
- Depois: → `no`.

**Fit.** Alto — espelha o lab de `PermitRootLogin`; só config; EC2 privada; sem PoC de login.

---

### 2. CONFIG-SSH-EMPTY-PASSPHRASE-KEY

**Problema.** Uma chave privada de laboratório é gerada **sem** passphrase e fica utilizável por quem obtiver o arquivo. Não é bug de OpenSSH — é má higiene de credencial. **CONFIG**.

**Exemplo não técnico.** É a chave de casa sem segredo extra no chaveiro: quem achar o chaveiro físico abre a porta na hora. Com senha na chave (passphrase), achar o arquivo ainda exige o “PIN” mental.

**Correção.** Remover a chave insegura do lab **ou** regenerar com passphrase (`ssh-keygen -p` / nova chave); garantir que só o dono lê o arquivo.

**Verify.**  
- Antes: chave existe e `ssh-keygen -y -f ... -P ''` aceita passphrase vazia (só inspeção local).  
- Depois: chave ausente **ou** passphrase vazia rejeitada / arquivo `0600` + política documentada “com passphrase”.

**Fit.** Alto — claro, reversível, sem rede; cuidado: não versionar chave real.

---

### 3. CONFIG-UFW-DISABLED

**Problema.** O firewall do host (`ufw`) está **inativo**, deixando a política de filtragem local desligada. Em EC2 o Security Group já filtra, mas o lab ensina defesa em profundidade. **CONFIG**.

**Exemplo não técnico.** O condomínio tem portaria na rua (Security Group), mas as portas internas dos apartamentos estão todas destrancadas (ufw off). Se alguém já estiver no corredor, nada impede ir de porta em porta.

**Correção.** `ufw default deny incoming`, permitir só o necessário (ex. SSH da rede privada), `ufw --force enable`.

**Verify.**  
- Antes: `ufw status` → `inactive`.  
- Depois: `ufw status` → `active` (+ regra SSH presente).

**Fit.** Alto — comando Bash simples; verificável; sem PoC de scan.

---

### 4. CONFIG-SUDOERS-NOPASSWD

**Problema.** Um usuário de lab tem `NOPASSWD: ALL` (ou amplo) em `/etc/sudoers.d/`, podendo virar root sem digitar senha. **CONFIG** clássica de hardening.

**Exemplo não técnico.** O estagiário ganha um crachá de “síndico permanente” que abre qualquer sala sem pedir confirmação. Basta alguém usar o crachá (ou a sessão do estagiário) e o prédio inteiro fica acessível.

**Correção.** Remover o drop-in `NOPASSWD` ou restringir a comandos mínimos **com** senha; `chmod 0440` no arquivo; validar com `visudo -c`.

**Verify.**  
- Antes: `sudo -n -l -U <user>` lista comandos sem pedir senha / mostra `NOPASSWD`.  
- Depois: `sudo -n true` falha para esse usuário (ou lista sem `NOPASSWD`).

**Fit.** Alto — padrão CIS; inspeção clara; EC2 privada.

---

### 5. CONFIG-SUDOERS-UNRESTRICTED

**Problema.** Arquivo em `/etc/sudoers.d/` concede `ALL=(ALL:ALL) ALL` **e** está com permissão fraca (ex. `0644` ou world-writable). Combina política ampla + risco de adulteração. **CONFIG**.

**Exemplo não técnico.** Além do crachá de síndico, a lista de quem pode ser síndico está afixada no mural com caneta livre: qualquer um risca o próprio nome. Política ampla + lista editável = desastre administrativo.

**Correção.** Restringir regras (ou remover o drop-in de lab); `chown root:root` + `chmod 0440`; `visudo -c`.

**Verify.**  
- Antes: `stat -c '%a %U:%G' /etc/sudoers.d/99-tcc-lab` ≠ `440 root:root` **e/ou** regra `ALL` presente.  
- Depois: modo `0440`, root:root, regra restrita ou arquivo removido; `visudo -c` OK.

**Fit.** Alto — combina bem com o tema “permissões”; distinto do NOPASSWD puro se focar em permissão do arquivo + regra ampla.

---

### 6. CONFIG-PRIVATE-KEY-0644

**Problema.** Chave privada SSH (ou TLS de lab) com modo `0644` (legível por outros usuários locais). **CONFIG** de permissão POSIX.

**Exemplo não técnico.** A chave do carro fica no porta-luvas **destrancado** e com o vidro aberto: qualquer passageiro do banco de trás pode pegar. O certo é trancar o porta-luvas (só o dono lê).

**Correção.** `chmod 600` (e `chown` do usuário dono); opcionalmente mover para `~/.ssh/` com dir `700`.

**Verify.**  
- Antes: `stat -c '%a' /path/to/id_lab` → `644` (ou pior).  
- Depois: → `600` (ou ausente se política for remover).

**Fit.** Alto — mínimo, ótimo para pipeline CONFIG; distinto de world-writable de “token” se focar em chave criptográfica.

---

### 7. CONFIG-BASHRC-PATH-HIJACK

**Problema.** O `.bashrc` (ou `/etc/profile.d/tcc-lab.sh`) coloca um diretório **gravável por todos** (ex. `/tmp/tcc-bin` ou `~/worldwrite/bin`) **no início** do `PATH`. Um usuário local poderia plantar um executável com nome de comando comum. O lab **não** executa hijack — só detecta PATH inseguro. **CONFIG**.

**Exemplo não técnico.** A empresa manda o entregador procurar ferramentas “na primeira caixa da prateleira”. Essa primeira caixa é a caixa aberta da recepção, onde qualquer visitante pode colocar uma chave de fenda falsa. Quem pega a ferramenta sem olhar usa a falsa.

**Correção.** Remover o prefixo inseguro do PATH; garantir que dirs no PATH não sejam world-writable; recarregar shell de teste.

**Verify.**  
- Antes: script de verify confere que `PATH` começa com dir world-writable conhecido do lab.  
- Depois: esse dir não está no PATH (ou não é world-writable).

**Fit.** Alto — pedagógico; verificação só por inspeção; sem payload.

---

### 8. CONFIG-SYSCTL-IP-FORWARD

**Problema.** `net.ipv4.ip_forward=1` habilitado sem o host ser roteador. Aumenta superfície se a máquina for comprometida ou mal posicionada na rede. **CONFIG** de kernel sysctl.

**Exemplo não técnico.** O apartamento deixa a porta dos fundos aberta “só para passar encomendas ao vizinho”, transformando a sala em corredor. Se ninguém precisa de corredor, a porta dos fundos deve ficar fechada.

**Correção.** `sysctl -w net.ipv4.ip_forward=0` + drop-in `/etc/sysctl.d/99-tcc-lab.conf` com `net.ipv4.ip_forward=0`.

**Verify.**  
- Antes: `sysctl -n net.ipv4.ip_forward` → `1`.  
- Depois: → `0`.

**Fit.** Médio-Alto — uma linha; claro; sem PoC de roteamento.

---

### 9. CONFIG-NGINX-AUTOINDEX

**Problema.** `nginx` (pacote leve de lab) com `autoindex on` em um site local, listando arquivos do document root. **CONFIG** de serviço web; bind preferencialmente `127.0.0.1`.

**Exemplo não técnico.** A secretária deixa a gaveta de pastas aberta na mesa: qualquer um que entre na sala vê a lista de todos os documentos, mesmo sem abrir cada um. Desligar a listagem é fechar a gaveta — ainda se pode pedir um arquivo específico com nome conhecido, mas a vitrine some.

**Correção.** `autoindex off;` (ou remover o server block de lab); `nginx -t && systemctl reload nginx`.

**Verify.**  
- Antes: `curl -sI http://127.0.0.1:<port>/` ou corpo HTML indica listagem / conf contém `autoindex on`.  
- Depois: `autoindex off` efetivo; resposta sem índice de diretório.

**Fit.** Médio-Alto — precisa instalar nginx; ainda assim remediável por conf; sem exposição pública se bind local + SG fechado.

---

### 10. CONFIG-FAIL2BAN-ABSENT

**Problema.** `fail2ban` está instalado no lab mas o serviço está **parado/desabilitado**, ou o pacote foi removido após baseline “com proteção”. O caso ensina controle de serviço de defesa. **CONFIG** (ausência/estado), não CVE.

**Exemplo não técnico.** O porteiro eletrônico existe, mas está no modo “folga”: a caixa está na parede, desligada. Quem tenta várias senhas na fechadura não é barrado pelo sistema de alertas.

**Correção.** `apt-get install -y fail2ban` (se ausente) + `systemctl enable --now fail2ban`; jail mínima SSH se desejado.

**Verify.**  
- Antes: `systemctl is-active fail2ban` → `inactive` **ou** pacote ausente.  
- Depois: `active` + `is-enabled` true (critério documentado).

**Fit.** Médio — um pouco mais “presença de ferramenta” do que misconfig clássica; ainda assim verificável e remediável por Bash. Preferir se quiser diversidade operacional.

---

## Como escolher as 3

Sugestão de combinação equilibrada (apenas orientação):

1. **Autenticação/acesso:** `CONFIG-SSH-PASSWORD-AUTH` ou `CONFIG-SUDOERS-NOPASSWD`  
2. **Permissões/arquivo:** `CONFIG-PRIVATE-KEY-0644` ou opcional `CONFIG-WORLD-WRITABLE-SENSITIVE`  
3. **Rede/host:** `CONFIG-UFW-DISABLED` ou `CONFIG-SYSCTL-IP-FORWARD` ou opcional `CONFIG-LOCAL-HTTP-BIND`

Evitar duplicar demais com a já selecionada `CONFIG-SSH-PERMIT-ROOT` (não pegar *só* variantes SSH sem diversificar).

## Próximo passo

Responder com os **3 IDs** aprovados (mistura de opcionais + extras permitida). Até lá: só documentação.
