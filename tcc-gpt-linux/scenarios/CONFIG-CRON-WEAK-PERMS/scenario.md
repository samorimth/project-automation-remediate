# CONFIG-CRON-WEAK-PERMS — proposta (pendente de aprovação)

**Tipo:** **CONFIG** (permissões fracas em job cron — **não é CVE**)  
**Status de aprovação:** pendente  
**AMI / instância vulnerável preparada:** não  
**Recurso pago AWS criado:** não  
**Script gerado por GPT:** não  
**Portfólio:** lab #5 de 10 (`PORTFOLIO_10_LABS.md`)

## Identificador

CONFIG-CRON-WEAK-PERMS

## Descrição

Job em `/etc/cron.d/tcc-lab-job` criado **world-writable** (`0666`). Em sistemas reais, permissões frouxas em cron.d são rejeitadas ou representam risco de alteração maliciosa. Remediação: `0644` (ou `0600`) e `root:root`.

O job em si só escreve um heartbeat em `/var/tmp/tcc-lab-cron.ok` (sem rede, sem privilégio extra além do que cron já tem).

## Estado inseguro (prepare)

- Arquivo `/etc/cron.d/tcc-lab-job` modo `0666`, dono `root:root`.  
- Conteúdo mínimo e inócuo (echo para arquivo de lab).

## Estado seguro esperado (remediate)

- Modo `0644` ou `0600`; dono `root:root`; **sem** escrita para other (`S_IWOTH` ausente).

## Procedimentos (após aprovação + autorização de recursos)

### prepare

```bash
cat > /etc/cron.d/tcc-lab-job <<'EOF'
# TCC lab — job inócuo; permissões propositalmente inseguras
* * * * * root /bin/echo tcc-lab-cron-ok > /var/tmp/tcc-lab-cron.ok
EOF
chown root:root /etc/cron.d/tcc-lab-job
chmod 0666 /etc/cron.d/tcc-lab-job
```

### verify_before

```bash
stat -c '%a %U:%G %n' /etc/cron.d/tcc-lab-job
# esperado inseguro: 666 ...
```

### remediate (alvo do script gerado)

Corrigir permissões do job (`chmod 0644` / `chown root:root`). Não é necessário alterar o schedule.

### verify_after

```bash
stat -c '%a %U:%G %n' /etc/cron.d/tcc-lab-job
python3 - <<'PY'
import os, stat
st = os.stat("/etc/cron.d/tcc-lab-job")
assert not (st.st_mode & (stat.S_IWOTH | stat.S_IWGRP)), "ainda gravavel por group/other"
assert st.st_uid == 0 and st.st_gid == 0
print("ok_cron_perms")
PY
```

## Por que é seguro para o lab

- Job só toca `/var/tmp/tcc-lab-cron.ok`.  
- Sem exploração de race; só inspeção de permissões.  
- Removível ao apagar o arquivo de lab.  
- EC2 privada.

## Referências (hardening, não CVE)

- `man cron` / práticas de permissões em `/etc/cron.d`
