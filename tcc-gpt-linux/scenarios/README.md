# Cenários CVE — Fase 2

Este diretório registra candidatos a CVE para o laboratório. A **CVE-2024-38428 (`wget`)** foi **aprovada** como primeiro experimento. As demais fichas permanecem alternativas / pendentes.

## Estado em 12 de novembro de 2026

| Item | Situação |
| --- | --- |
| Status de aprovação | **CVE-2024-38428 aprovada** e executada. **CVE-2024-32487 (`less`) aprovada** e executada em 12/11/2026. As outras fichas continuam alternativas |
| Recursos AWS | a pilha do wget e a pilha do less foram destruídas depois da coleta. Não há NAT nem VPC do laboratório ligados. A instância CopySpider, parada e fora deste experimento, não foi alterada |
| Provisionamento | tentativa 5 em `us-east-2` criou a pilha; tentativas anteriores na região default e em `sa-east-1` foram negadas pelo SCP `p-xikt6vmn` |
| Estado vulnerável | provado: `wget 1.21.4-1ubuntu4` na instância `i-04da3315297ec6c04` |
| Chamadas à API e execuções | quatro chamadas, três scripts, três remediações comprovadas por versão; a classificação do protocolo novo é INCONCLUSIVO porque a mesma EC2 foi reutilizada; ver `docs/resultados_tcc.md` |
| Resultado inventado | **não** |

O SCP `p-xikt6vmn` bloqueou EC2 na região default e em `sa-east-1` (tentativa 4 em `results/CVE-2024-38428/execucao_bloqueada.json`). Em `us-east-2` a sonda passou. Na tentativa 5, `enable_nat_gateway` e `enable_execution` estavam ligados e o `apply` concluiu. Esse bloqueio não é o estado atual: a pilha da tentativa 5 já foi criada e, depois do experimento, destruída.

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

Detalhes, links oficiais e procedimentos previstos estão em `scenarios/<CVE>/scenario.md`. Para a CVE aprovada, `prepare.sh`, `verify_before.sh` e `verify_after.sh` foram executados via SSM. `prepare.sh --apply` restaurou `wget 1.21.4-1ubuntu4` antes das repetições 3 e 4.

## Artefatos de preparação (CVE-2024-38428)

| Arquivo | Função |
| --- | --- |
| [`CVE-2024-38428/scenario.md`](CVE-2024-38428/scenario.md) | Ficha completa (versões oficiais, refs, procedimentos) |
| [`CVE-2024-38428/prepare.sh`](CVE-2024-38428/prepare.sh) | Downgrade pinado do `.deb` histórico (com `--check` / dry-run) |
| [`CVE-2024-38428/verify_before.sh`](CVE-2024-38428/verify_before.sh) | Evidência `before` por versão do pacote |
| [`CVE-2024-38428/verify_after.sh`](CVE-2024-38428/verify_after.sh) | Evidência `after` pós-remediação |

## Próximo passo

A Fase 6 desta CVE está consolidada em `docs/resultados_tcc.md` e `results/summary.csv`. As outras nove fichas continuam alternativas: não têm `prepare.sh` nem execução. Abrir uma delas exige nova aprovação e novo provisionamento, com a frase `AUTORIZO_RECURSOS_PAGOS`.

## Aviso sobre backports e pacotes históricos

No Ubuntu, o número “aparente” do upstream pode parecer antigo e ainda assim já conter o patch de segurança. A comparação válida é sempre a **versão do pacote Debian/Ubuntu** no CVE Tracker / USN / OSV para `noble`, não o número upstream isolado. AMIs recentes já trazem correções: a preparação típica é obter `.deb` no Launchpad/archive.ubuntu.com e fazer *downgrade* pinado.
