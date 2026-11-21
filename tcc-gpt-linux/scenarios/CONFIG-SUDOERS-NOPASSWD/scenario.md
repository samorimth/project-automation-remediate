# CONFIG-SUDOERS-NOPASSWD — proposta (selecionada / aprovada)

**Tipo:** **CONFIG** (privilégios locais via `sudo` — **não é CVE**)  
**Status de aprovação:** **selecionada / aprovada** (pendente de preparação — sem AMI/GPT/terraform até autorização)  
**AMI / instância vulnerável preparada:** não  
**Recurso pago AWS criado:** não  
**Script gerado por GPT:** não  
**Portfólio:** CONFIG #4 de 4 — quarteto completo (`PORTFOLIO_10_LABS.md`)

## Identificador

CONFIG-SUDOERS-NOPASSWD

## Descrição

Estado inseguro intencional: usuário de laboratório com regra `NOPASSWD: ALL` (ou equivalente amplo) em `/etc/sudoers.d/`, podendo elevar a root **sem digitar senha**. Remediação: remover o drop-in inseguro ou restringir a comandos mínimos **com** senha; validar com `visudo -c`.

O laboratório **não** explora escalação ofensiva; prova-se só a política efetiva (`sudo -n -l` / falha de `sudo -n`).

## Estado inseguro (prepare)

- Usuário de lab (ex.: `tcc-lab`) presente.  
- Drop-in `/etc/sudoers.d/99-tcc-lab-nopasswd` com `tcc-lab ALL=(ALL) NOPASSWD: ALL`.  
- Modo `0440` no ficheiro; `visudo -c` OK.

## Estado seguro esperado (remediate)

- Drop-in `NOPASSWD` removido **ou** substituído por regra sem `NOPASSWD` (senha exigida).  
- Critério independente: `sudo -n true` como o usuário de lab **falha**; `sudo -n -l -U tcc-lab` não lista `NOPASSWD` amplo.

## Procedimentos (após aprovação + autorização de recursos)

### prepare

```bash
id tcc-lab >/dev/null 2>&1 || useradd -m -s /bin/bash tcc-lab
printf '%s\n' 'tcc-lab ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/99-tcc-lab-nopasswd
chmod 0440 /etc/sudoers.d/99-tcc-lab-nopasswd
visudo -c -f /etc/sudoers.d/99-tcc-lab-nopasswd
```

### verify_before

```bash
sudo -n -l -U tcc-lab
# esperado inseguro: lista com NOPASSWD
sudo -u tcc-lab sudo -n true && echo nopasswd_ok
# esperado inseguro: exit 0
```

### remediate (alvo do script gerado)

Remover `/etc/sudoers.d/99-tcc-lab-nopasswd` (ou editar para exigir senha / escopo mínimo); `visudo -c`. Sem PoC de exploração.

### verify_after

```bash
! sudo -u tcc-lab sudo -n true
# esperado seguro: falha (pede senha / sem NOPASSWD)
sudo -n -l -U tcc-lab 2>/dev/null | grep -i NOPASSWD && exit 1 || echo ok_sem_nopasswd
```

## Por que é seguro para o lab

- Só altera política `sudoers` de um usuário de lab; EC2 privada.  
- Sem CVE, sem payload, sem exploração.  
- Verificação por `sudo -n` / listagem de regras.  
- Reversível: apagar o drop-in de lab.

## Referências (hardening, não CVE)

- `man sudoers` — `NOPASSWD`  
- CIS Benchmark / práticas de least privilege em hosts Ubuntu
