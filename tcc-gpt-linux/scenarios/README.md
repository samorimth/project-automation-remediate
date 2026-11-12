# Cenários CVE — Fase 2

Este diretório registra candidatos a CVE para o laboratório. A **CVE-2024-38428 (`wget`)** foi **aprovada** como primeiro experimento. As demais fichas permanecem alternativas / pendentes.

## Estado desta entrega

| Item | Situação |
| --- | --- |
| Status de aprovação | **CVE-2024-38428 aprovada** (1º experimento); demais **alternativas/pendentes** |
| AMI / EC2 vulnerável preparada | **não** (só documentação + scripts locais de preparação) |
| Recurso pago AWS criado | **não** |
| `terraform apply` / `destroy` | **não executados** |
| Chamada à API OpenAI | **não** |
| Script gerado por GPT | **não** |
| Resultado experimental inventado | **não** |

### Autorização ainda necessária para prova em EC2 real

Documentar e versionar os mecanismos de preparação **não** autoriza provisionamento. Provar a vulnerabilidade em EC2 real ainda exige autorização **separada e explícita** para:

1. Ligar `enable_nat_gateway` e `enable_execution` em `terraform.tfvars` local (não versionado).
2. Executar `python -m src.main provision --authorize AUTORIZO_RECURSOS_PAGOS`.
3. Só então rodar os scripts de `scenarios/CVE-2024-38428/` via SSM na instância privada.

Sem esses passos, o trabalho permanece offline / docs-only.

## Critérios usados na seleção

- Documentação oficial da Canonical (Ubuntu CVE Tracker e/ou USN).
- Versões vulnerável e corrigida conhecidas para Ubuntu 24.04 LTS (`noble`), alinhada à AMI padrão da Fase 1.
- Remediação por atualização de pacote (`apt`), sem exploração ativa.
- Verificação independente antes/depois via `dpkg -s`, `apt-cache policy` e comparação com a versão corrigida publicada.
- Pacote instalável (ou reinstalável em versão antiga) em EC2 privada, sem expor serviço à Internet.
- Correção disponível no repositório público (sem depender de Ubuntu Pro / ESM).
- Diversidade de pacotes (utilitários locais, cliente de rede, biblioteca, VCS), não só clones de `binutils`/`elfutils`.

Fontes: [Ubuntu CVE Tracker](https://ubuntu.com/security/), [Ubuntu Security Notices](https://ubuntu.com/security/notices), [OSV / USN JSON](https://osv.dev/) e, complementarmente, NVD. Versões vulneráveis são as publicadas no OSV da Canonical para `Ubuntu:24.04:LTS`; a versão de preparação sugerida é a última vulnerável registrada para `noble`.

## Candidatos (~10)

| CVE | Status | Pacote | Prioridade Ubuntu | NVD CVSS | Versão vulnerável (ex.) | Versão corrigida | USN | Reprodutibilidade | Impacto (1 linha) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [CVE-2024-38428](CVE-2024-38428/scenario.md) | **aprovada** | `wget` | medium | 9.1 | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.1` | [USN-6852-1](https://ubuntu.com/security/notices/USN-6852-1) | fácil | `userinfo` de URI mal interpretado; conexão a host inesperado. |
| [CVE-2025-1372](CVE-2025-1372/scenario.md) | alternativa | `elfutils` | medium | 5.3 | `0.190-1.1build4.1` | `0.190-1.1ubuntu0.1` | [USN-7369-1](https://ubuntu.com/security/notices/USN-7369-1) | fácil | Overflow local em `eu-readelf` ao processar arquivo malicioso (DoS). |
| [CVE-2025-0840](CVE-2025-0840/scenario.md) | alternativa | `binutils` | medium | 5.0 | `2.42-4ubuntu2.3` | `2.42-4ubuntu2.4` | [USN-7306-1](https://ubuntu.com/security/notices/USN-7306-1) | média | Overflow em `objdump` com entrada inadequada; risco de falha/código. |
| [CVE-2024-11053](CVE-2024-11053/scenario.md) | alternativa | `curl` | low | 3.4 | `8.5.0-2ubuntu10.5` | `8.5.0-2ubuntu10.6` | [USN-7162-1](https://ubuntu.com/security/notices/USN-7162-1) | fácil | Vazamento de senha `.netrc` em redirecionamento HTTP. |
| [CVE-2024-32487](CVE-2024-32487/scenario.md) | alternativa | `less` | medium | 8.6 | `590-2ubuntu2` | `590-2ubuntu2.1` | [USN-6756-1](https://ubuntu.com/security/notices/USN-6756-1) | fácil | Execução de comando via newline em nome de arquivo no pager. |
| [CVE-2024-5742](CVE-2024-5742/scenario.md) | alternativa | `nano` | low | 6.7 | `7.2-2build1` | `7.2-2ubuntu0.1` | [USN-7064-1](https://ubuntu.com/security/notices/USN-7064-1) | fácil | Escalação via arquivo temporário inseguro se `nano` for interrompido. |
| [CVE-2025-48384](CVE-2025-48384/scenario.md) | alternativa | `git` | high | 8.0 | `1:2.43.0-1ubuntu7.2` | `1:2.43.0-1ubuntu7.3` | [USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1) | média | Falha no tratamento de CRLF em config/submódulo; risco de código. |
| [CVE-2025-64505](CVE-2025-64505/scenario.md) | alternativa | `libpng1.6` | medium | 6.1 | `1.6.43-5build1` | `1.6.43-5ubuntu0.1` | [USN-7924-1](https://ubuntu.com/security/notices/USN-7924-1) | média | Over-read em heap ao processar PNG com índices de paleta inválidos. |
| [CVE-2025-45582](CVE-2025-45582/scenario.md) | alternativa | `tar` | medium | 4.1 | `1.35+dfsg-3ubuntu0.1` | `1.35+dfsg-3ubuntu0.2` | [USN-8510-1](https://ubuntu.com/security/notices/USN-8510-1) | média | Travessia/overwrite via symlink em extrações sequenciais de TAR. |
| [CVE-2024-12084](CVE-2024-12084/scenario.md) | alternativa | `rsync` | high | 9.8 | `3.2.7-1ubuntu1` | `3.2.7-1ubuntu1.1` | [USN-7206-1](https://ubuntu.com/security/notices/USN-7206-1) | média | Overflow em heap no protocolo rsync; lab usa só versão, sem daemon. |

Detalhes, links oficiais e procedimentos previstos estão em `scenarios/<CVE>/scenario.md`. Para a CVE aprovada, há também rascunhos Bash em `scenarios/CVE-2024-38428/` (`prepare.sh`, `verify_before.sh`, `verify_after.sh`) destinados a execução futura via SSM — **não** executados nesta entrega contra EC2.

## Artefatos de preparação (CVE-2024-38428)

| Arquivo | Função |
| --- | --- |
| [`CVE-2024-38428/scenario.md`](CVE-2024-38428/scenario.md) | Ficha completa (versões oficiais, refs, procedimentos) |
| [`CVE-2024-38428/prepare.sh`](CVE-2024-38428/prepare.sh) | Downgrade pinado do `.deb` histórico (com `--check` / dry-run) |
| [`CVE-2024-38428/verify_before.sh`](CVE-2024-38428/verify_before.sh) | Evidência `before` por versão do pacote |
| [`CVE-2024-38428/verify_after.sh`](CVE-2024-38428/verify_after.sh) | Evidência `after` pós-remediação |

## Próximo passo (decisão do autor)

1. **Manter offline / docs-only** — nenhuma ação AWS; scripts ficam versionados para uso posterior.
2. **Autorizar recursos pagos** — ligar NAT + execução, frase `AUTORIZO_RECURSOS_PAGOS`, provisionar EC2 privada e só então aplicar `prepare.sh` via SSM.

Geração de script por GPT, execução automatizada e medição **não** fazem parte desta entrega.

## Aviso sobre backports e pacotes históricos

No Ubuntu, o número “aparente” do upstream pode parecer antigo e ainda assim já conter o patch de segurança. A comparação válida é sempre a **versão do pacote Debian/Ubuntu** no CVE Tracker / USN / OSV para `noble`, não o número upstream isolado. AMIs recentes já trazem correções: a preparação típica é obter `.deb` no Launchpad/archive.ubuntu.com e fazer *downgrade* pinado.
