# CONFIG-LOCAL-HTTP-BIND — proposta (pendente de aprovação)

**Tipo:** **CONFIG** (serviço desnecessário escutando em interface ampla — **não é CVE**)  
**Status de aprovação:** pendente  
**AMI / instância vulnerável preparada:** não  
**Recurso pago AWS criado:** não  
**Script gerado por GPT:** não  
**Portfólio:** lab #6 de 10 (`PORTFOLIO_10_LABS.md`)

## Identificador

CONFIG-LOCAL-HTTP-BIND

## Descrição

Serviço HTTP mínimo de laboratório (Python `http.server` ou unit systemd) iniciado escutando em **`0.0.0.0:18080`**. Estado seguro: bind apenas em **`127.0.0.1:18080`**, ou serviço parado.

A instância permanece **sem IP público** e o security group **sem entrada**; o lab demonstra configuração de bind, não exposição real à Internet.

## Estado inseguro (prepare)

- Processo/unit `tcc-lab-http` escutando `0.0.0.0:18080` (todas as interfaces).  
- Conteúdo estático mínimo (diretório `/var/tmp/tcc-lab-http` com `index.html` de lab).

## Estado seguro esperado (remediate)

- Escuta apenas em `127.0.0.1:18080`, **ou** serviço inativo / porta fechada.  
- Critério: `ss -ltn` (ou equivalente) não mostra `*:18080` / `0.0.0.0:18080`.

## Procedimentos (após aprovação + autorização de recursos)

### prepare

```bash
install -d -m 0755 /var/tmp/tcc-lab-http
printf '%s\n' '<html><body>tcc-lab-http</body></html>' > /var/tmp/tcc-lab-http/index.html
# unit de lab (exemplo): ExecStart=/usr/bin/python3 -m http.server 18080 --bind 0.0.0.0
# working directory /var/tmp/tcc-lab-http; enable + start
```

(Implementação concreta do unit fica para a fase de preparação aprovada; não subir porta 80/443 padrão.)

### verify_before

```bash
ss -ltn | awk '$4 ~ /:18080$/'
# esperado inseguro: linha com 0.0.0.0:18080 ou *:18080
```

### remediate (alvo do script gerado)

Reconfigurar bind para `127.0.0.1` e reiniciar o unit, **ou** parar/desabilitar o serviço de lab. Sem scanner de rede externo; sem exploração.

### verify_after

```bash
ss -ltn | awk '$4 ~ /:18080$/{print}'
# seguro: vazio (parado) OU somente 127.0.0.1:18080 / [::1]:18080
python3 - <<'PY'
import subprocess, re
out = subprocess.check_output(["ss", "-ltn"], text=True)
bad = [ln for ln in out.splitlines() if re.search(r"0\.0\.0\.0:18080|\*:18080|:::18080", ln)]
assert not bad, bad
print("ok_bind")
PY
```

## Por que é seguro para o lab

- Porta alta (`18080`), conteúdo estático de lab.  
- Sem IP público / sem SG de entrada — o “risco” é só a **configuração de bind** na máquina.  
- Sem exploração ativa; verificação com `ss`.  
- Unit de lab facilmente removível.

## Referências (hardening, não CVE)

- Princípio de menor superfície / bind localhost para serviços administrativos
