# CONFIG-WORLD-WRITABLE-SENSITIVE — proposta (pendente de aprovação)

**Tipo:** **CONFIG** (permissões inseguras — **não é CVE**)  
**Status de aprovação:** pendente  
**AMI / instância vulnerável preparada:** não  
**Recurso pago AWS criado:** não  
**Script gerado por GPT:** não  
**Portfólio:** lab #4 de 10 (`PORTFOLIO_10_LABS.md`)

## Identificador

CONFIG-WORLD-WRITABLE-SENSITIVE

## Descrição

Arquivo sensível de laboratório (`/etc/tcc-lab/secret.env`) criado **world-writable** (`0666`). Remediação: restringir a `0600` e dono `root:root`.

Não usa `/etc/shadow` real para evitar risco operacional; o arquivo é **sintético** e só existe no lab.

## Estado inseguro (prepare)

- Arquivo `/etc/tcc-lab/secret.env` com conteúdo placeholder (sem segredo real de produção).  
- Modo `0666`, dono `root:root`.

## Estado seguro esperado (remediate)

- Modo `0600` (ou mais restritivo, sem bits de escrita para group/other).  
- Dono `root:root`.

## Procedimentos (após aprovação + autorização de recursos)

### prepare

```bash
install -d -m 0755 /etc/tcc-lab
printf '%s\n' 'TCC_LAB_TOKEN=placeholder-not-a-real-secret' > /etc/tcc-lab/secret.env
chown root:root /etc/tcc-lab/secret.env
chmod 0666 /etc/tcc-lab/secret.env
```

### verify_before

```bash
stat -c '%a %U:%G %n' /etc/tcc-lab/secret.env
# esperado inseguro: 666 root:root ...
```

### remediate (alvo do script gerado)

Corrigir permissões/dono do arquivo sensível (ex.: `chmod 0600`, `chown root:root`). Sem leitura ofensiva de outros arquivos do sistema.

### verify_after

```bash
MODE="$(stat -c '%a' /etc/tcc-lab/secret.env)"
OWNER="$(stat -c '%U:%G' /etc/tcc-lab/secret.env)"
# seguro se MODE for 600 (ou 400) e OWNER root:root; e sem escrita para other
python3 - <<'PY'
import os, stat
st = os.stat("/etc/tcc-lab/secret.env")
assert not (st.st_mode & stat.S_IWOTH), "ainda world-writable"
print("ok_permissoes")
PY
```

## Por que é seguro para o lab

- Arquivo **sintético** sob `/etc/tcc-lab/`; não altera shadow/passwd.  
- Verificação só com `stat` / bits POSIX.  
- Sem exploração; remediação é `chmod`/`chown`.  
- EC2 privada.

## Referências (hardening, não CVE)

- POSIX file permissions; práticas de “secrets on disk”
