# CONFIG-FAIL2BAN-ABSENT — proposta (selecionada / aprovada)

**Tipo:** **CONFIG** (estado de serviço de defesa — **não é CVE**)  
**Status de aprovação:** **selecionada / aprovada** (pendente de preparação — sem AMI/GPT/terraform até autorização)  
**AMI / instância vulnerável preparada:** não  
**Recurso pago AWS criado:** não  
**Script gerado por GPT:** não  
**Portfólio:** CONFIG #3 de 4 (`PORTFOLIO_10_LABS.md`)

## Identificador

CONFIG-FAIL2BAN-ABSENT

## Descrição

Estado inseguro intencional: `fail2ban` instalado (ou esperado no baseline do lab) mas **parado/desabilitado**, ou pacote ausente após baseline “com proteção”. Remediação: instalar se necessário e `systemctl enable --now fail2ban`.

O laboratório **não** simula força bruta; prova-se só o estado do serviço (`systemctl`).

## Estado inseguro (prepare)

- `fail2ban` instalado **e** `systemctl disable --now fail2ban`, **ou** pacote removido após instalação de referência.  
- Critério documentado no prepare: `inactive` / `disabled` (ou pacote ausente).

## Estado seguro esperado (remediate)

- Pacote presente; serviço `active` e `enabled`.  
- Opcional: jail mínima SSH presente (sem teste de ban).

## Procedimentos (após aprovação + autorização de recursos)

### prepare

```bash
apt-get update -qq
apt-get install -y fail2ban
systemctl disable --now fail2ban
```

### verify_before

```bash
systemctl is-active fail2ban || true
systemctl is-enabled fail2ban || true
# esperado inseguro: inactive / disabled (ou pacote ausente)
```

### remediate (alvo do script gerado)

`apt-get install -y fail2ban` (se ausente) + `systemctl enable --now fail2ban`. Sem PoC de ataque.

### verify_after

```bash
systemctl is-active fail2ban
# esperado: active
systemctl is-enabled fail2ban
# esperado: enabled
```

## Por que é seguro para o lab

- Só controla estado de serviço; sem exploração.  
- EC2 privada; não abre portas.  
- Verificação por `systemctl` / presença do pacote.  
- Reversível: parar/desabilitar de novo no cleanup.

## Referências (hardening, não CVE)

- `fail2ban` — documentação upstream / man pages  
- Defesa em profundidade em hosts Ubuntu (presença de ferramenta de ban)
