# CONFIG-NGINX-AUTOINDEX — proposta (selecionada)

**Tipo:** **CONFIG** (configuração de serviço web — **não é CVE**)  
**Status de aprovação:** **selecionada** (pendente de preparação — sem AMI/GPT/terraform até autorização)  
**AMI / instância vulnerável preparada:** não  
**Recurso pago AWS criado:** não  
**Script gerado por GPT:** não  
**Portfólio:** CONFIG #2 de 4 (`PORTFOLIO_10_LABS.md`)

## Identificador

CONFIG-NGINX-AUTOINDEX

## Descrição

Estado inseguro intencional: `nginx` com `autoindex on` em um site de laboratório (bind preferencialmente `127.0.0.1`), expondo listagem de diretório do document root. Remediação: `autoindex off` (ou remover o server block de lab).

O laboratório **não** explora varredura externa; prova-se só a configuração efetiva (conf + resposta local).

## Estado inseguro (prepare)

- Pacote `nginx` instalado; site de lab com `autoindex on` e document root com ficheiros placeholder.  
- Listen em `127.0.0.1` (EC2 privada; sem exposição pública).

## Estado seguro esperado (remediate)

- `autoindex off;` efetivo (ou site de lab removido).  
- Critério independente: conf sem `autoindex on` ativo **e/ou** resposta HTTP sem índice de diretório.

## Procedimentos (após aprovação + autorização de recursos)

### prepare

```bash
apt-get update -qq
apt-get install -y nginx
install -d -m 0755 /var/www/tcc-lab
printf '%s\n' 'placeholder-a' > /var/www/tcc-lab/a.txt
printf '%s\n' 'placeholder-b' > /var/www/tcc-lab/b.txt
cat > /etc/nginx/sites-available/tcc-lab <<'EOF'
server {
    listen 127.0.0.1:8080;
    root /var/www/tcc-lab;
    autoindex on;
}
EOF
ln -sfn /etc/nginx/sites-available/tcc-lab /etc/nginx/sites-enabled/tcc-lab
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
```

### verify_before

```bash
grep -R --include='*.conf' 'autoindex on' /etc/nginx/ || true
curl -s http://127.0.0.1:8080/ | head
# esperado inseguro: autoindex on na conf e/ou HTML de listagem
```

### remediate (alvo do script gerado)

Definir `autoindex off;` (ou remover o site de lab); `nginx -t && systemctl reload nginx`. Sem PoC de exploração.

### verify_after

```bash
! grep -R --include='*.conf' 'autoindex on' /etc/nginx/ || grep -R 'autoindex off' /etc/nginx/sites-enabled/
# e/ou: curl local sem índice de diretório
```

## Por que é seguro para o lab

- Bind **localhost**; EC2 privada; SG sem entrada da Internet.  
- Apenas muda conf de nginx; sem CVE nem payload.  
- Verificação por leitura de conf / resposta local.  
- Reversível: remover site de lab.

## Referências (hardening, não CVE)

- `nginx` `autoindex` — documentação oficial  
- Práticas de endurecimento de servidor web (sem listagem de diretórios)
