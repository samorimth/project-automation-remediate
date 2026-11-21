# Candidatos de alto impacto — Ubuntu (≈2021–2026)

Pesquisa para escolher CVEs de **maior impacto / notoriedade** alinhados ao lab do TCC.  
**Fontes:** Ubuntu CVE Tracker, Ubuntu Security Notices (USN), páginas oficiais Canonical.  
**Data da consulta:** 21 de novembro de 2026. **Nenhuma CVE ou score inventado.**

## Critérios de “Fit para ESTE lab”

| Fit | Significado |
| --- | --- |
| **Alto** | USN Canonical; remediação por `apt`; verificação por versão de pacote; reproduzível em 22.04/24.04 sem PoC de exploração |
| **Médio** | Impacto alto e USN ok, mas kernel (pin/reboot), downgrade histórico difícil, ou SO alvo só parcialmente afetado |
| **Baixo** | Famoso, porém 22.04/24.04 não afetados no tracker, ou Ubuntu released “Not affected”, ou sucesso dependeria de exploit |

**Já no portfólio / feito** (marcar e não reescolher como “novo”):  
CVE-2024-38428 (`wget`), CVE-2024-32487 (`less`), CVE-2024-11053 (`curl`), CVE-2024-5742 (`nano`), CVE-2025-1372 (`elfutils`), CVE-2025-48384 (`git`).

Reservas já documentadas no inventário: `binutils`, `libpng`, `tar`, `rsync` — ver [`README.md`](README.md) / [`PORTFOLIO_10_LABS.md`](PORTFOLIO_10_LABS.md).

**Nenhum ambiente foi preparado nesta pesquisa.**

Para avaliar **o que cada falha explora** (mecanismo + impacto se não corrigida, sem PoC): seção [O que cada CVE explora](#o-que-cada-cve-explora-mecanismo--impacto-se-não-corrigido) e, no portfólio, [Portfólio — o que cada CVE explora](#portfólio--o-que-cada-cve-explora-pendentes--executadas).

---

## Tabela — candidatos de alto impacto (ordenados por ano, depois impacto)

| CVE | Ano | Componente | Severidade (Ubuntu / NVD) | Problema (1 frase) | USN / Canonical | Fit lab | Motivo do fit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [CVE-2021-3156](https://ubuntu.com/security/CVE-2021-3156) (Baron Samedit) | 2021 | `sudo` | Ubuntu **High** · NVD **7.8** | Falha no `sudo`/`sudoedit` permite que usuário local vire administrador. | [USN-4705-1](https://ubuntu.com/security/notices/USN-4705-1) | **Baixo** | Altíssimo impacto histórico; releases 22.04/24.04 já nasceram corrigidas no tracker — lab atual exigiria pacote/SO mais antigo. |
| [CVE-2021-3493](https://ubuntu.com/security/CVE-2021-3493) (OverlayFS) | 2021 | kernel / OverlayFS | Ubuntu **High** · NVD **8.8** | Bug no OverlayFS permite escalar privilégios locais no Ubuntu. | [USN-4917-1](https://ubuntu.com/security/notices/USN-4917-1) (também USN-4916-1) | **Baixo** | Kernel + 22.04/24.04 **Not affected** no tracker; difícil pinar versão vulnerável no alvo LTS atual. |
| [CVE-2021-33909](https://ubuntu.com/security/CVE-2021-33909) (Sequoia) | 2021 | kernel | Ubuntu **High** · NVD **7.8** | Overflow no sistema de arquivos virtual pode dar root a usuário local. | [USN-5016-1](https://ubuntu.com/security/notices/USN-5016-1) (série USN-501x) | **Baixo** | Kernel; 22.04/24.04 **Not affected**. |
| [CVE-2021-4034](https://ubuntu.com/security/CVE-2021-4034) (PwnKit / polkit) | 2021–2022 | `policykit-1` / `pkexec` | Ubuntu **High** · NVD **7.8** | Ferramenta de “pedir permissão de admin” maltrata argumentos e pode virar root. | [USN-5252-1](https://ubuntu.com/security/notices/USN-5252-1) | **Médio** | Pacote userland + USN; verificação por versão ok **sem PoC**. Jammy já traz versão corrigida de fábrica — precisa `.deb` histórico (ex. focal) no lab 22.04/24.04. |
| [CVE-2022-0847](https://ubuntu.com/security/CVE-2022-0847) (Dirty Pipe) | 2022 | kernel (pipes) | Ubuntu **High** · NVD **7.8** | Usuário local pode sobrescrever arquivos “só leitura” via pipe e escalar privilégios. | [USN-5317-1](https://ubuntu.com/security/notices/USN-5317-1) · [KB DirtyPipe](https://ubuntu.com/security/vulnerabilities/dirtypipe) | **Baixo** | Muito famoso; 22.04/24.04 **Not affected**; kernel + reboot; pin histórico difícil. |
| [CVE-2023-0386](https://ubuntu.com/security/CVE-2023-0386) (OverlayFS) | 2023 | kernel / OverlayFS | Ubuntu **High** · NVD **7.8** | Cópia de arquivo com capacidades no OverlayFS pode elevar privilégios. | [USN-6025-1](https://ubuntu.com/security/notices/USN-6025-1) (jammy) · [USN-6043-1](https://ubuntu.com/security/notices/USN-6043-1) | **Médio** | Bom para **22.04**; 24.04 **Not affected**; kernel exige pin + reboot; lab sem PoC ainda verifica versão do kernel. |
| [CVE-2023-2640](https://ubuntu.com/security/CVE-2023-2640) + [CVE-2023-32629](https://ubuntu.com/security/CVE-2023-32629) (GameOver(lay)) | 2023 | kernel / OverlayFS (Ubuntu) | Ubuntu **High** · NVD **7.8** | Falhas Ubuntu-específicas no OverlayFS permitem virar “quase root” localmente. | [USN-6250-1](https://ubuntu.com/security/notices/USN-6250-1) · [USN-6251-1](https://ubuntu.com/security/notices/USN-6251-1) | **Médio** | Altíssimo impacto em cloud Ubuntu; kernel HWE/variantes; 24.04 **Not affected**; pin + reboot. |
| [CVE-2023-4911](https://ubuntu.com/security/CVE-2023-4911) (Looney Tunables) | 2023 | `glibc` / `ld.so` | Ubuntu **High** · NVD **7.8** | Variável `GLIBC_TUNABLES` maltratada pode dar root via programas setuid. | [USN-6409-1](https://ubuntu.com/security/notices/USN-6409-1) | **Alto** | Pacote `libc6` onipresente; USN clara; verifica por versão; **22.04** afetado; 24.04 já com fix na linha de release — preferir jammy para estado vulnerável histórico; reboot após update. |
| [CVE-2023-6246](https://ubuntu.com/security/CVE-2023-6246) (glibc syslog) | 2024* | `glibc` | Ubuntu **Medium** · NVD **7.8** | Overflow em `syslog`/`__vsyslog_internal` pode crashar ou escalar privilégios. | [USN-6620-1](https://ubuntu.com/security/notices/USN-6620-1) | **Baixo** | Impacto real, mas Ubuntu **Medium**; 22.04 **Not affected**; 24.04 corrigido na versão de release. |
| [CVE-2024-1086](https://ubuntu.com/security/CVE-2024-1086) (netfilter / nf_tables) | 2024 | kernel / netfilter | Ubuntu **High** · NVD **7.8** | Use-after-free no filtro de rede local pode dar root. | [USN-6707-1](https://ubuntu.com/security/notices/USN-6707-1) (também USN-6700-1 / 6702) | **Médio** | Alto impacto (KEV/notoriedade); **22.04** sim; **24.04 Not affected**; kernel + reboot. |
| [CVE-2024-3094](https://ubuntu.com/security/CVE-2024-3094) (xz / liblzma backdoor) | 2024 | `xz-utils` | Ubuntu **Critical** · NVD **10.0** | Backdoor no xz poderia comprometer sshd — mas **não entrou** em releases Ubuntu. | Tracker: [CVE-2024-3094](https://ubuntu.com/security/CVE-2024-3094) (sem USN de release afetado) | **Baixo** | Notório mundialmente; Canonical: releases LTS **Not affected** (só `noble-proposed` removido). Sem lab útil no modelo “apt fix em 22.04/24.04”. |
| [CVE-2024-6387](https://ubuntu.com/security/CVE-2024-6387) (regreSSHion) | 2024 | `openssh` / `sshd` | Ubuntu **High** · NVD **8.1** | Race no servidor SSH pode permitir acesso remoto sem credenciais. | [USN-6859-1](https://ubuntu.com/security/notices/USN-6859-1) · [blog Canonical](https://ubuntu.com/blog/ubuntu-regresshion-security-fix) | **Alto** | Perfeito para o lab: 22.04 e 24.04 com fix USN; remediação `apt install openssh-server`; sucesso = versão ≥ corrigida (**sem** PoC). |
| [CVE-2024-47176](https://ubuntu.com/security/CVE-2024-47176) (cups-browsed) | 2024 | `cups-browsed` | Ubuntu **Medium** · NVD **5.3** (cadeia RCE em combinação) | Serviço de descoberta de impressoras confia demais na rede e, com outras falhas, pode levar a código remoto. | [USN-7042-1](https://ubuntu.com/security/notices/USN-7042-1) (melhorias USN-7042-2/3) | **Médio** | Bom em **24.04** (pacote dedicado); remediação por update; prioridade Ubuntu só Medium; lab sem exploração ainda funciona por versão. |
| [CVE-2024-48990](https://ubuntu.com/security/CVE-2024-48990) (needrestart; família 48991/48992/11003) | 2024 | `needrestart` | Ubuntu **High** · NVD **7.8** | Ferramenta que reinicia serviços após update pode ser enganada e executar código como root. | [USN-7117-1](https://ubuntu.com/security/notices/USN-7117-1) · [blog Canonical](https://ubuntu.com/blog/needrestart-local-privilege-escalation) | **Alto** | Excelente fit: instalado por padrão em Server 22.04+; USN clara; `apt` + versão; 22.04 e 24.04; sem PoC. |
| [CVE-2024-12084](https://ubuntu.com/security/CVE-2024-12084) | 2024 | `rsync` | Ubuntu **High** · NVD **9.8** | Overflow no protocolo rsync (risco grave se daemon/cliente vulnerável). | [USN-7206-1](https://ubuntu.com/security/notices/USN-7206-1) | **Alto**† | Já é **reserva** do inventário; remediação por versão; lab não precisa daemon/PoC. |
| [CVE-2025-26465](https://ubuntu.com/security/CVE-2025-26465) | 2025 | `openssh` (cliente) | Ubuntu **Medium** · NVD **6.8** | Com opção DNS de host key, cliente pode aceitar servidor falso (MITM em cenário raro). | [USN-7270-1](https://ubuntu.com/security/notices/USN-7270-1) | **Baixo** | USN ok, mas impacto/prioridade menores que regreSSHion; opção não default. |
| [CVE-2025-48384](https://ubuntu.com/security/CVE-2025-48384) | 2025 | `git` | Ubuntu **High** · NVD **8.0** | Git trata mal caminhos/submódulo; risco de código indesejado. | [USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1) | **Alto**† | **Já no portfólio** (pendente aprovação). |

\*Publicação/disclosure em 2024; CVE id 2023.  
†Já no inventário do repositório (portfólio ou reserva).

---

## O que cada CVE explora (mecanismo / impacto se não corrigido)

Textos em português para **avaliar candidatos**. Descrevem a condição abusada e o que um atacante poderia alcançar **se o sistema permanecer sem patch**. **Não** incluem passo a passo de exploração, payloads ou PoC.  
Analogias de uma linha são opcionais e não técnicas.

### CVE-2021-3156 — Baron Samedit (`sudo`)

- **O que explora:** Overflow em heap no `sudo`/`sudoedit` ao tratar argumentos em modo “shell”. A rotina que monta a string do comando calcula o tamanho do buffer sem contar corretamente certos caracteres de escape (barra invertida no fim do argumento); o desbalanceamento entre “escapar” e “desescapar” permite escrita além do buffer alocado. Como `sudo` roda com privilégio elevado, um usuário local sem privilégios administrativos poderia, em versões vulneráveis, obter execução como root. Afeta a fronteira de privilégio local (user → root), sem precisar de rede.
- **Correção típica:** Atualizar `sudo` via `apt` (pacote corrigido na [USN-4705-1](https://ubuntu.com/security/notices/USN-4705-1)).
- **Fit lab:** **Baixo**
- *Analogia:* Um porteiro que, ao “desfazer aspas” no pedido, copia além do papel e acaba com o carimbo de administrador no bolso do visitante.

### CVE-2021-3493 — OverlayFS / capacidades (`kernel`)

- **O que explora:** O OverlayFS no kernel Ubuntu não validava corretamente, em relação a *user namespaces*, a aplicação de *file capabilities* em arquivos do sistema de arquivos subjacente. Combinado com namespaces sem privilégio e a possibilidade (no Ubuntu) de montagens overlay não privilegiadas, um usuário local podia fazer com que um arquivo ganhasse capacidades privilegiadas indevidas. Resultado típico sem patch: escalação de privilégio local até root.
- **Correção típica:** Atualizar o kernel Ubuntu e reiniciar ([USN-4917-1](https://ubuntu.com/security/notices/USN-4917-1); também USN-4916-1).
- **Fit lab:** **Baixo**
- *Analogia:* Colar um “crachá de síndico” num arquivo comum porque a portaria do condomínio não checou se o crachá era válido naquele andar.

### CVE-2021-33909 — Sequoia / `seq_file` (`kernel`)

- **O que explora:** Overflow de inteiro (conversão unsigned→signed) na alocação de buffers do *virtual file system* (`seq_file`). Um usuário local podia provocar alocação insuficiente e escrita fora dos limites no kernel. Sem correção: negação de serviço (crash) ou execução de código no contexto do kernel, com escalação a root.
- **Correção típica:** Atualizar o kernel e reiniciar ([USN-5016-1](https://ubuntu.com/security/notices/USN-5016-1) e série USN-501x).
- **Fit lab:** **Baixo**
- *Analogia:* Pedir uma caixa “do tamanho do pedido” com a conta errada (número negativo disfarçado) e estourar a prateleira do depósito.

### CVE-2021-4034 — PwnKit (`pkexec` / policykit)

- **O que explora:** O `pkexec` (SUID-root) assumia que sempre haveria pelo menos um argumento (`argv[0]`). Com lista de argumentos vazia (`argc == 0`), a leitura/escrita “do próximo argumento” cai sobre a área contígua das variáveis de ambiente. Isso permite reintroduzir variáveis que o carregador normalizou/removeu em programas setuid, quebrando a fronteira de sanitização de ambiente. Usuário local sem autenticação administrativa podia obter root.
- **Correção típica:** Atualizar `policykit-1` / `pkexec` via `apt` ([USN-5252-1](https://ubuntu.com/security/notices/USN-5252-1)).
- **Fit lab:** **Médio**
- *Analogia:* Um formulário que, sem nenhum campo preenchido, começa a editar a “lista de anotações do lado” (o ambiente) como se fosse o pedido.

### CVE-2022-0847 — Dirty Pipe (`kernel` / pipes)

- **O que explora:** Em pipes do kernel, novos `pipe_buffer` podiam herdar *flags* antigas (incluindo `PIPE_BUF_FLAG_CAN_MERGE`) por falta de inicialização em caminhos de `splice`/cópia. Com essa flag “suja”, uma escrita no pipe podia fundir dados na página do *page cache* de um arquivo aberto só para leitura. Abusa a fronteira de permissão de escrita em arquivos: usuário local podia alterar conteúdo de arquivos que não deveria poder modificar e, a partir disso, escalar a root.
- **Correção típica:** Atualizar o kernel e reiniciar ([USN-5317-1](https://ubuntu.com/security/notices/USN-5317-1); [KB DirtyPipe](https://ubuntu.com/security/vulnerabilities/dirtypipe)).
- **Fit lab:** **Baixo**
- *Analogia:* Um cano que, por um adesivo “pode misturar” esquecido, grava na página do livro que você só abriu para ler.

### CVE-2023-0386 — OverlayFS copy-up com capacidades (`kernel`)

- **O que explora:** Falha no *copy-up* do OverlayFS: ao copiar um arquivo com capacidades/`setuid` de uma montagem `nosuid` para outra, o mapeamento de uid/capabilities não era tratado de forma segura. Um usuário local podia obter um executável privilegiado no destino e elevar privilégios. Mecanismo: fronteira de montagem + metadados privilegiados mal copiados.
- **Correção típica:** Atualizar o kernel (ex. jammy [USN-6025-1](https://ubuntu.com/security/notices/USN-6025-1); [USN-6043-1](https://ubuntu.com/security/notices/USN-6043-1)) e reiniciar.
- **Fit lab:** **Médio**
- *Analogia:* Fotocopiar um crachá VIP de uma zona “sem VIP” para a zona comum — e o crachá continuar válido.

### CVE-2023-2640 + CVE-2023-32629 — GameOver(lay) (`kernel` / OverlayFS Ubuntu)

- **O que explora:** Duas falhas Ubuntu-específicas no OverlayFS: checagens de permissão incompletas ao definir atributos estendidos privilegiados (`xattrs`) em operações de *copy-up*/montagem. Usuário sem privilégio podia marcar arquivos do *upper layer* com metadados privilegiados. Em kernels Ubuntu afetados (muito usados em cloud), isso permitia escalação local a privilégios elevados (“quase root”/root conforme o cenário).
- **Correção típica:** Atualizar o kernel Ubuntu e reiniciar ([USN-6250-1](https://ubuntu.com/security/notices/USN-6250-1), [USN-6251-1](https://ubuntu.com/security/notices/USN-6251-1)).
- **Fit lab:** **Médio**
- *Analogia:* Um elevador de carga que deixa qualquer morador colar o adesivo “carga especial” sem o síndico olhar.

### CVE-2023-4911 — Looney Tunables (`glibc` / `ld.so`)

- **O que explora:** Buffer overflow no carregador dinâmico (`ld.so`) ao processar a variável de ambiente `GLIBC_TUNABLES`. Valores malformados/excessivos estouram um buffer interno durante o *parse*. Como o carregador roda no contexto de binários setuid, um usuário local podia controlar a memória do processo privilegiado e executar código como root. Abusa o canal “ambiente → loader setuid”.
- **Correção típica:** Atualizar `libc6` / `glibc` via `apt` ([USN-6409-1](https://ubuntu.com/security/notices/USN-6409-1)); reinício recomendado para processos já carregados.
- **Fit lab:** **Alto**
- *Analogia:* Um “ajuste fino” escrito no bilhete do motorista que, se for longo demais, rasga o painel e troca quem está no volante.

### CVE-2023-6246 — glibc `syslog` / `__vsyslog_internal`

- **O que explora:** Overflow em heap na função interna de `syslog`/`vsyslog` quando `openlog` não foi chamado (ou `ident` é NULL) e o nome do programa (`basename` de `argv[0]`) excede ~1024 bytes. O registro de log copia esse nome para um buffer insuficiente. Em processos privilegiados que logam assim, o impacto sem patch pode ir de crash a escalação local.
- **Correção típica:** Atualizar `libc6` ([USN-6620-1](https://ubuntu.com/security/notices/USN-6620-1)).
- **Fit lab:** **Baixo**
- *Analogia:* O carimbo do livro de ponto só reserva uma linha para o nome — se o nome for um parágrafo, a tinta invade a página seguinte.

### CVE-2024-1086 — netfilter / `nf_tables` (`kernel`)

- **O que explora:** Use-after-free (e risco de double-free) no netfilter/`nf_tables`: vereditos de hook com valores de “drop error” positivos mal interpretados fazem o caminho `NF_DROP` liberar memória que ainda pode ser usada. Usuário local com capacidade de configurar regras nftables (ou em contextos onde isso é possível) podia corromper memória do kernel → crash ou execução com privilégio de kernel/root.
- **Correção típica:** Atualizar o kernel e reiniciar ([USN-6707-1](https://ubuntu.com/security/notices/USN-6707-1); também USN-6700-1 / 6702).
- **Fit lab:** **Médio**
- *Analogia:* Rasgar um bilhete de “descartar pacote” e depois tentar ler o mesmo bilhete — a mesa do filtro já deu o papel para outro.

### CVE-2024-3094 — xz / liblzma backdoor

- **O que explora:** Não é um bug clássico de parsing: código malicioso foi introduzido nos *tarballs* upstream do xz (a partir de 5.6.0). O build extrai um objeto pré-compilado disfarçado e altera funções da `liblzma`, de modo que software ligado a ela (notavelmente caminhos relacionados a `sshd`) poderia interceptar/modificar tráfego. Em Ubuntu LTS **released**, o tracker indica **Not affected** (versão afetada só chegou a `noble-proposed` e foi removida).
- **Correção típica:** Em distros afetadas, remover/atualizar `xz-utils`/`liblzma` para build limpa. Em Ubuntu LTS: sem USN de release afetado — ver [CVE-2024-3094](https://ubuntu.com/security/CVE-2024-3094).
- **Fit lab:** **Baixo**
- *Analogia:* Uma peça sobressalente “oficial” que, na fábrica, veio com um chip escondido — mas nessa marca (Ubuntu LTS) a peça nunca chegou à prateleira.

### CVE-2024-6387 — regreSSHion (`openssh` / `sshd`)

- **O que explora:** Race condition no tratamento de sinais do `sshd` (regressão de CVE-2006-5051): se a autenticação não completa a tempo (`LoginGraceTime`), o manipulador de sinal pode correr em momento inseguro em relação ao estado do processo filho. Atacante remoto **não autenticado** pode, em condições de timing difíceis, obter execução de código no servidor SSH — ou seja, acesso sem credenciais. Vetor: rede → daemon privilegiado.
- **Correção típica:** Atualizar `openssh-server` / `openssh` via `apt` ([USN-6859-1](https://ubuntu.com/security/notices/USN-6859-1); [blog Canonical](https://ubuntu.com/blog/ubuntu-regresshion-security-fix)).
- **Fit lab:** **Alto**
- *Analogia:* O segurança da portaria atende o interfone e, no exato instante do timeout, se distrai — alguém pode passar sem mostrar documento (em teoria; na prática o “timing” é difícil).

### CVE-2024-47176 — `cups-browsed`

- **O que explora:** O serviço de descoberta de impressoras escuta de forma ampla (`INADDR_ANY:631`) e confia em anúncios/pacotes da rede, podendo disparar pedidos IPP (`Get-Printer-Attributes`) a URL controlada por atacante. Sozinho é principalmente abuso de confiança na rede; **em cadeia** com outras falhas CUPS (atributos/filtros), pode chegar a execução remota de comandos sem autenticação quando se imprime numa “impressora” maliciosa.
- **Correção típica:** Atualizar `cups-browsed` (ou `cups-filters` em releases onde o código ainda vivia lá) via `apt` ([USN-7042-1](https://ubuntu.com/security/notices/USN-7042-1); melhorias USN-7042-2/3).
- **Fit lab:** **Médio**
- *Analogia:* O concierge anota qualquer cartão de “nova impressora na rede” e liga para o número do cartão — às vezes o número é de um impostor.

### CVE-2024-48990 — `needrestart` (família 48991/48992/…)

- **O que explora:** Após atualizações, o `needrestart` (frequentemente como root) inspeciona processos e pode invocar interpretadores (ex. Python) herdando ambiente do processo alvo. Um usuário local podia influenciar variáveis como `PYTHONPATH` para que o interpretador carregasse módulos sob controle do atacante **com UID 0**. Abusa a fronteira “scanner privilegiado lê ambiente de processo não privilegiado”.
- **Correção típica:** Atualizar `needrestart` via `apt` ([USN-7117-1](https://ubuntu.com/security/notices/USN-7117-1); [blog Canonical](https://ubuntu.com/blog/needrestart-local-privilege-escalation)).
- **Fit lab:** **Alto**
- *Analogia:* O encarregado que reinicia serviços pega a “caixa de ferramentas” do estagiário sem olhar o conteúdo — e a caixa foi trocada.

### CVE-2024-12084 — `rsync` (reserva do inventário)

- **O que explora:** Overflow em heap no protocolo/tratamento de checksums do rsync. Cliente ou daemon vulnerável que processa dados de peer não confiável pode corromper memória. Sem patch, em cenários de daemon/exposição de protocolo, o impacto chega a execução remota de código (NVD crítico). No lab do TCC a prova é só por versão — sem subir daemon.
- **Correção típica:** Atualizar `rsync` via `apt` ([USN-7206-1](https://ubuntu.com/security/notices/USN-7206-1)).
- **Fit lab:** **Alto**†
- *Analogia:* Conferir a lista de volumes da mudança com uma calculadora que estoura e começa a escrever no livro-caixa.

### CVE-2025-26465 — OpenSSH cliente (`VerifyHostKeyDNS`)

- **O que explora:** Com a opção não padrão `VerifyHostKeyDNS` habilitada, o cliente OpenSSH trata mal certos códigos de erro na verificação da chave do host. Em cenário de MITM, após esgotar recursos de memória do cliente (complexidade alta), o cliente pode aceitar um servidor impostor. Abusa a fronteira de autenticação do *host key* no cliente, não o daemon.
- **Correção típica:** Atualizar `openssh-client` / `openssh` ([USN-7270-1](https://ubuntu.com/security/notices/USN-7270-1)).
- **Fit lab:** **Baixo**
- *Analogia:* Conferir o RG do porteiro pelo DNS da rua — e, sob estresse/memória cheia, aceitar um RG falso.

### CVE-2025-48384 — `git` (também no portfólio)

- **O que explora:** Tratamento inconsistente de CRLF/CR em valores de configuração e caminhos de submódulo: na leitura o Git remove CRLF final; na escrita, CR final pode não ser citado corretamente e se perde. Na inicialização de submódulo, caminho com CR pode fazer o checkout ir para diretório diferente do esperado; combinado com symlink e hook `post-checkout`, pode executar código sem a intenção do usuário. Abusa parsing de path/config na fronteira “repo → working tree / hooks”.
- **Correção típica:** Atualizar `git` via `apt` ([USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1)).
- **Fit lab:** **Alto**†
- *Analogia:* O rótulo da caixa tem um caractere invisível no fim — a mudança entrega no depósito errado, onde já há um bilhete “ligar o motor”.

---

## Já no portfólio (marcar — impacto “médio/útil”, não os maiores headlines)

| CVE | Ano | Pacote | Ubuntu / NVD | USN | Status no TCC |
| --- | --- | --- | --- | --- | --- |
| [CVE-2024-38428](https://ubuntu.com/security/CVE-2024-38428) | 2024 | `wget` | medium / 9.1 | [USN-6852-1](https://ubuntu.com/security/notices/USN-6852-1) | **EXECUTADO — SUCESSO** |
| [CVE-2024-32487](https://ubuntu.com/security/CVE-2024-32487) | 2024 | `less` | medium / 8.6 | [USN-6756-1](https://ubuntu.com/security/notices/USN-6756-1) | **EXECUTADO — FALHA** |
| [CVE-2024-11053](https://ubuntu.com/security/CVE-2024-11053) | 2024 | `curl` | low / 3.4 | [USN-7162-1](https://ubuntu.com/security/notices/USN-7162-1) | portfólio / pendente |
| [CVE-2024-5742](https://ubuntu.com/security/CVE-2024-5742) | 2024 | `nano` | low / 6.7 | [USN-7064-1](https://ubuntu.com/security/notices/USN-7064-1) | portfólio / pendente |
| [CVE-2025-1372](https://ubuntu.com/security/CVE-2025-1372) | 2025 | `elfutils` | medium / ~5.3 | [USN-7369-1](https://ubuntu.com/security/notices/USN-7369-1) | portfólio / pendente |
| [CVE-2025-48384](https://ubuntu.com/security/CVE-2025-48384) | 2025 | `git` | high / 8.0 | [USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1) | portfólio / pendente |

### Portfólio — o que cada CVE explora (pendentes + executadas)

Mesmo formato; útil para comparar com os headlines acima. Fit lab do portfólio = alinhamento ao desenho atual (apt + versão em 24.04, sem PoC) — em geral **Alto** para estes pacotes userland.

#### CVE-2024-38428 — `wget` (EXECUTADO — SUCESSO)

- **O que explora:** Parsing incorreto de URLs: componentes de “userinfo” (parte antes de `@`) podem ser interpretados como hostname. Um usuário induzido a baixar de um endereço enganoso conecta-se a host diferente do pretendido (phishing / redirecionamento de confiança). Impacto: confidencialidade/integridade do download, não RCE local típica.
- **Correção típica:** Atualizar `wget` ([USN-6852-1](https://ubuntu.com/security/notices/USN-6852-1)).
- **Fit lab:** **Alto** (já executado com sucesso)
- *Analogia:* O mensageiro lê o “apartamento” como se fosse o prédio e entrega no endereço errado.

#### CVE-2024-32487 — `less` (EXECUTADO — FALHA)

- **O que explora:** Nomes de arquivo com newline (e aspas mal tratadas) no pager `less`, especialmente com `LESSOPEN`, podem ser interpretados de forma que o shell execute comandos além de só paginar o arquivo. Vetor local/induzido (abrir arquivo “armadilha”). Sem patch: execução de comando no contexto do usuário (ou do processo que abriu o `less`).
- **Correção típica:** Atualizar `less` ([USN-6756-1](https://ubuntu.com/security/notices/USN-6756-1)).
- **Fit lab:** **Alto** (lab executado; resultado operacional FALHA — ver docs do TCC)
- *Analogia:* O rótulo do dossiê tem uma segunda linha escondida que a secretária cumpre sem querer.

#### CVE-2024-11053 — `curl` / `libcurl` (pendente)

- **O que explora:** Ao usar credenciais de `.netrc` e seguir redirecionamento HTTP, o `curl` pode enviar a senha do primeiro host para o host de destino quando a entrada do `.netrc` “casa” parcialmente com o hostname do redirect (senha ou login omitidos de forma ambígua). Abusa a fronteira de escopo de credencial em redirects. Sem patch: vazamento de segredo para terceiro (impacto de confidencialidade; prioridade Ubuntu low).
- **Correção típica:** Atualizar `curl` / `libcurl4t64` ([USN-7162-1](https://ubuntu.com/security/notices/USN-7162-1)).
- **Fit lab:** **Alto** (pacote cliente; pinagem fácil)
- *Analogia:* O carteiro leva o mesmo envelope com a senha do banco A para o banco B depois do aviso de “agência mudou”.

#### CVE-2024-5742 — `nano` (pendente)

- **O que explora:** Se o `nano` for interrompido no meio da edição, pode gravar arquivo de emergência com permissões inadequadas. Em cenário raro (editor rodando como root e processo morto por usuário sem privilégio), abre janela para abuso via arquivo temporário/symlink (race / permissão). Fronteira: arquivos temporários privilegiados vs. usuário local.
- **Correção típica:** Atualizar `nano` ([USN-7064-1](https://ubuntu.com/security/notices/USN-7064-1)).
- **Fit lab:** **Alto** (pacote único; cenário de abuso é incomum — severidade Ubuntu low)
- *Analogia:* O rascunho de emergência do gerente fica na mesa da sala comum.

#### CVE-2025-1372 — `elfutils` / `eu-readelf` (pendente)

- **O que explora:** Overflow / acesso inválido de memória em `eu-readelf` ao processar seções de arquivo ELF malformado (`dump_data_section` / `print_string_section`). Vetor local: induzir usuário ou script a inspecionar o arquivo. Impacto prático típico sem patch: crash / negação de serviço da ferramenta (não headline de root remoto).
- **Correção típica:** Atualizar `elfutils` e bibliotecas correlatas ([USN-7369-1](https://ubuntu.com/security/notices/USN-7369-1)).
- **Fit lab:** **Alto** (utilitário local; fácil)
- *Analogia:* O scanner de bagagem trava a esteira diante de uma mala montada para confundir o sensor.

#### CVE-2025-48384 — `git` (pendente)

Ver seção de alto impacto acima (mesmo mecanismo CRLF/path/submódulo). **Fit lab:** **Alto**† · [USN-7626-1](https://ubuntu.com/security/notices/USN-7626-1).

---

## Recomendação rápida para o TCC (só escolha, sem preparar ambiente)

Se quiser **substituir ou complementar** CVEs “menores” do portfólio por headlines de impacto, priorize **Fit Alto**:

1. **CVE-2024-6387** (`openssh`) — remoto, High, 22.04+24.04, apt + versão  
2. **CVE-2024-48990** (`needrestart`) — root local, High, Server default, apt + versão  
3. **CVE-2023-4911** (`glibc`) — High, ótimo em **22.04**; reboot  
4. Manter **CVE-2025-48384** (`git`) e/ou reserva **CVE-2024-12084** (`rsync`)  

Kernel (Dirty Pipe, OverlayFS, GameOver(lay), netfilter): ótimos para **capítulo de impacto**, fracos como lab “pin + verify” sob as regras atuais → **Médio/Baixo**.

PwnKit / Baron Samedit / Dirty Pipe: citar na revisão bibliográfica; **não** priorizar como lab em 22.04/24.04.

---

## Fontes consultadas

- [Ubuntu CVE Tracker](https://ubuntu.com/security/)  
- [Ubuntu Security Notices](https://ubuntu.com/security/notices)  
- Páginas CVE individuais listadas na tabela  
- Blogs Canonical: [regreSSHion](https://ubuntu.com/blog/ubuntu-regresshion-security-fix), [needrestart](https://ubuntu.com/blog/needrestart-local-privilege-escalation), [DirtyPipe KB](https://ubuntu.com/security/vulnerabilities/dirtypipe)
