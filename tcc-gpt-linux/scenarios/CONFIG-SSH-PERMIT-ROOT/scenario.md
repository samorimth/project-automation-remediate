# CONFIG-SSH-PERMIT-ROOT — proposta (pendente de aprovação)

**Tipo:** **CONFIG** (configuração insegura do SO — **não é CVE**)  
**Status de aprovação:** pendente  
**AMI / instância vulnerável preparada:** não  
**Recurso pago AWS criado:** não  
**Script gerado por GPT:** não  
**Portfólio:** lab #3 de 10 (`PORTFOLIO_10_LABS.md`)

## Identificador

CONFIG-SSH-PERMIT-ROOT

## Descrição

Estado inseguro intencional: `PermitRootLogin yes` no OpenSSH server. Remediação esperada: restringir login root via SSH (`PermitRootLogin prohibit-password` ou `no`), conforme hardening típico CIS/Ubuntu.

O laboratório **não** explora força bruta nem autenticação; prova-se só a configuração efetiva (`sshd -T`).

## Estado inseguro (prepare)

- Drop-in `/etc/ssh/sshd_config.d/99-tcc-lab-insecure.conf` com `PermitRootLogin yes`.
- `systemctl reload ssh` (ou `sshd`) sem abrir SG/IP público além do desenho privado já usado no lab.

## Estado seguro esperado (remediate)

- `PermitRootLogin prohibit-password` **ou** `PermitRootLogin no` no drop-in (ou remoção do drop-in inseguro + valor seguro efetivo).
- Critério independente: `sshd -T | awk '/^permitrootlogin /{print $2}'` ∈ {`prohibit-password`, `no`, `without-password`}.

## Procedimentos (após aprovação + autorização de recursos)

### prepare

```bash
install -d -m 0755 /etc/ssh/sshd_config.d
printf '%s\n' 'PermitRootLogin yes' > /etc/ssh/sshd_config.d/99-tcc-lab-insecure.conf
chmod 0644 /etc/ssh/sshd_config.d/99-tcc-lab-insecure.conf
systemctl reload ssh || systemctl reload sshd
```

### verify_before

```bash
sshd -T | awk '/^permitrootlogin /{print $2}'
# esperado para estado inseguro: yes
```

### remediate (alvo do script gerado)

Ajustar a configuração SSH para o estado seguro (editar/remover o drop-in inseguro; reload). Sem PoC de login.

### verify_after

```bash
sshd -T | awk '/^permitrootlogin /{print $2}'
# esperado: prohibit-password | no | without-password
```

## Por que é seguro para o lab

- Instância **privada**, sem IP público; SG sem entrada da Internet.  
- Apenas muda um parâmetro de `sshd`; não introduz CVE nem payload.  
- Verificação por leitura de config efetiva; sem autenticação de atacante.  
- Reversível: apagar o drop-in de lab.

## Referências (hardening, não CVE)

- `man sshd_config` — `PermitRootLogin`  
- CIS Benchmark / guias de hardening OpenSSH (contexto de configuração)
