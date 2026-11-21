# Descrições não técnicas — portfólio atualizado

Texto em português, acessível a leitores não técnicos (banca / TCC).  
Cada lab traz: o **problema** em poucas palavras, um **exemplo prático** do cotidiano (analogia — sem passo a passo de ataque) e a **correção** esperada.

**CVE** = falha em software (corrige-se atualizando o pacote).  
**CONFIG** = configuração ou permissão mal ajustada no sistema (corrige-se mudando a configuração — **não é CVE**).

O laboratório **não** reproduz exploração ativa; a prova técnica é versão de pacote (CVE) ou inspeção de configuração/permissões (CONFIG). Detalhes: [`PORTFOLIO_10_LABS.md`](PORTFOLIO_10_LABS.md), [`CONFIG_CANDIDATOS_EXTRA.md`](CONFIG_CANDIDATOS_EXTRA.md) e `scenarios/<id>/scenario.md`.

**Estado:** 2 CVE executadas; 6 CVE selecionadas (pendentes); 1 CONFIG selecionada; 3 CONFIG ainda a escolher.

---

## A. CVE executadas

### 1. CVE-2024-38428 — `wget` (CVE) — EXECUTADO — SUCESSO

**Problema.** O programa `wget` interpreta mal certos endereços: o que deveria ser só “login” do endereço pode ser lido como o nome do servidor, e a ferramenta pode conectar-se a um destino diferente do pretendido.

**Exemplo prático.** Imagine que você pede a um mensageiro para entregar uma carta no banco da sua cidade, mas o endereço veio escrito de forma confusa — com um detalhe no meio do texto que parece outro número de rua. O mensageiro, sem perceber, leva a carta para outro prédio. Você achava que falava com o banco; na verdade falava com um estranho.

**Correção.** Atualizar o pacote `wget` para a versão corrigida (USN-6852-1).

---

### 2. CVE-2024-32487 — `less` (CVE) — EXECUTADO — FALHA

**Problema.** O visualizador de texto `less` trata mal nomes de arquivo que contêm quebras de linha; em certas condições, abrir um arquivo com nome “armadilha” pode fazer o sistema executar comandos que o usuário não pediu.

**Exemplo prático.** Pense em uma pasta de documentos em que cada arquivo tem um rótulo na capa. Alguém cola um rótulo com duas linhas: na primeira, o título inocente (“relatório”); na segunda, uma ordem escondida (“abra também o cofre”). Quando a secretária só queria folhear o relatório, o sistema “lê” as duas linhas e cumpre a ordem extra.

**Correção.** Atualizar o pacote `less` para a versão corrigida (USN-6756-1).

---

## B. CONFIG selecionada

### 3. CONFIG-SSH-PERMIT-ROOT — login root via SSH (CONFIG) — SELECIONADA

**Problema.** O servidor de acesso remoto (SSH) está configurado para permitir que a conta **root** (o “administrador total” do sistema) entre com senha. Isso **não é CVE** — é configuração permissiva demais.

**Exemplo prático.** É como deixar a chave mestra do prédio na fechadura da porta da frente, com um cartaz “pode entrar quem souber a senha do síndico”. Qualquer um que descubra ou chute essa senha ganha controle de tudo.

**Correção.** Ajustar `PermitRootLogin` para `prohibit-password` ou `no` e recarregar o SSH.

---

## C. CONFIG opcionais (originais — ainda não confirmadas)

### CONFIG-WORLD-WRITABLE-SENSITIVE — segredo world-writable (CONFIG)

**Problema.** Arquivo sensível do laboratório com permissão de escrita para qualquer usuário (`0666`). **CONFIG**, não CVE.

**Exemplo prático.** Caderno com a senha do Wi‑Fi aberto na mesa da sala de espera, com caneta ao lado: qualquer visitante lê **e** troca o que está escrito.

**Correção.** Dono `root`, modo `0600`.

---

### CONFIG-CRON-WEAK-PERMS — job cron com permissão fraca (CONFIG)

**Problema.** Agendamento automático (`cron`) com permissão de escrita para todos. **CONFIG**, não CVE.

**Exemplo prático.** Agenda da empresa no mural do corredor, com caneta livre: um estranho risca “pagar as contas” e escreve outra ordem.

**Correção.** Job `0644` `root:root`.

---

### CONFIG-LOCAL-HTTP-BIND — serviço escutando em todas as interfaces (CONFIG)

**Problema.** Serviço HTTP de lab escuta em `0.0.0.0` em vez de só `127.0.0.1`. **CONFIG**, não CVE.

**Exemplo prático.** Interfone que atende também a rua e o prédio vizinho, não só a portaria.

**Correção.** Bind em `127.0.0.1` ou desligar o serviço.

---

## D. CVE selecionadas (pendentes de preparação)

### 4. CVE-2024-6387 — OpenSSH regreSSHion (CVE) — SELECIONADA

**Problema.** O servidor SSH tem uma “corrida” (race) no tratamento de sinais: em condições difíceis de timing, um atacante remoto sem senha poderia, em teoria, obter acesso indevido. O lab **não** tenta esse ataque — só confere se o pacote foi atualizado.

**Exemplo prático.** O segurança da portaria atende o interfone e, no exato instante do timeout, se distrai — alguém poderia passar sem mostrar documento (na prática o “timing” é difícil; no lab basta trocar a fechadura/firmware — o pacote).

**Correção.** Atualizar `openssh-server` / `openssh` (USN-6859-1) para versão ≥ `1:9.6p1-3ubuntu13.3` em Ubuntu 24.04.

---

### 5. CVE-2024-48990 — `needrestart` (CVE) — SELECIONADA

**Problema.** A ferramenta que decide quais serviços reiniciar após atualizações pode ser enganada e acabar executando código como administrador, herdando um ambiente manipulado.

**Exemplo prático.** O encarregado que reinicia os elevadores pega a “caixa de ferramentas” do estagiário sem olhar o conteúdo — e a caixa foi trocada. Quem reinicia serviços não deveria usar ferramentas plantadas por outra pessoa.

**Correção.** Atualizar `needrestart` (USN-7117-1) para ≥ `3.6-7ubuntu4.3` em 24.04.

---

### 6. CVE-2023-4911 — glibc Looney Tunables (CVE) — SELECIONADA

**Problema.** O carregador de programas (`ld.so` da biblioteca C) trata mal a variável `GLIBC_TUNABLES`; valores exagerados/malformados podem estourar um buffer e, em programas privilegiados, levar a privilégios de administrador. Em Ubuntu **24.04** a linha de release já veio corrigida; o lab vulnerável histórico costuma usar **22.04**.

**Exemplo prático.** Um “ajuste fino” escrito no bilhete do motorista que, se for longo demais, rasga o painel e troca quem está no volante.

**Correção.** Atualizar `libc6` (USN-6409-1); em jammy ≥ `2.35-0ubuntu3.4`; reinício recomendado.

---

### 7. CVE-2024-12084 — `rsync` (CVE) — SELECIONADA

**Problema.** Overflow de memória no protocolo/`rsync` ao tratar certos dados; em cenários reais o impacto pode ser grave. No lab a prova é **só pela versão do pacote** — sem subir daemon nem abrir porta.

**Exemplo prático.** Conferir a lista de volumes da mudança com uma calculadora que estoura e começa a escrever no livro-caixa.

**Correção.** Atualizar `rsync` (USN-7206-1) para ≥ `3.2.7-1ubuntu1.1` em 24.04.

---

### 8. CVE-2025-48384 — `git` (CVE) — SELECIONADA

**Problema.** O Git trata mal certos caracteres especiais em caminhos de configuração e submódulo: o checkout pode ir para um lugar diferente do esperado e, em combinação com outros truques, pode acabar executando código sem a intenção do usuário.

**Exemplo prático.** Você pede à mudança que leve as caixas para o “depósito 3”. No rótulo, um detalhe quase invisível faz entregar no **depósito 8** — onde já há um bilhete pedindo para “ligar o motor ao chegar”.

**Correção.** Atualizar `git` (USN-7626-1) para ≥ `1:2.43.0-1ubuntu7.3` em 24.04.

---

### 9. CVE-2024-11053 — `curl` e vazamento de senha em redirecionamento (CVE) — SELECIONADA

**Problema.** O cliente `curl`, ao usar senhas em `.netrc` e seguir um redirecionamento HTTP, pode em certos casos enviar a senha do primeiro site para o segundo.

**Exemplo prático.** Você entrega ao carteiro o envelope com a senha do banco A. No caminho, um aviso diz “vá ao banco B”. O carteiro leva o **mesmo envelope** para o B.

**Correção.** Atualizar `curl` / `libcurl` (USN-7162-1) para ≥ `8.5.0-2ubuntu10.6` em 24.04.

---

## E. CVE substituídas (fora da seleção atual)

Mantidas só como reserva / histórico do inventário — **não** entram no portfólio selecionado:

| ID | Pacote | Nota |
| --- | --- | --- |
| CVE-2024-5742 | `nano` | Substituída pelas CVE de alto impacto selecionadas |
| CVE-2025-1372 | `elfutils` | Substituída pelas CVE de alto impacto selecionadas |

---

## F. CONFIG extras (novas propostas)

Descrições completas (problema / exemplo / correção / verify / fit): [`CONFIG_CANDIDATOS_EXTRA.md`](CONFIG_CANDIDATOS_EXTRA.md).

Resumo em uma frase:

| ID | Em uma frase, se não corrigir… |
| --- | --- |
| CONFIG-SSH-PASSWORD-AUTH | A portaria aceita senha numérica além do cartão. |
| CONFIG-SSH-EMPTY-PASSPHRASE-KEY | A chave de casa não tem PIN no chaveiro. |
| CONFIG-UFW-DISABLED | As portas internas do corredor estão destrancadas. |
| CONFIG-SUDOERS-NOPASSWD | O estagiário tem crachá de síndico sem pedir confirmação. |
| CONFIG-SUDOERS-UNRESTRICTED | A lista de síndicos está no mural com caneta livre. |
| CONFIG-PRIVATE-KEY-0644 | A chave do carro está no porta-luvas aberto. |
| CONFIG-BASHRC-PATH-HIJACK | A primeira caixa de ferramentas é a da recepção. |
| CONFIG-SYSCTL-IP-FORWARD | A porta dos fundos vira corredor sem necessidade. |
| CONFIG-NGINX-AUTOINDEX | A gaveta de pastas fica aberta na mesa. |
| CONFIG-FAIL2BAN-ABSENT | O porteiro eletrônico existe, mas está desligado. |

---

## Resumo rápido (seleção atual)

| # | ID | Tipo | Status | Em uma frase… |
| --- | --- | --- | --- | --- |
| 1 | CVE-2024-38428 | CVE | EXECUTADO — SUCESSO | O download pode ir ao “prédio errado”. |
| 2 | CVE-2024-32487 | CVE | EXECUTADO — FALHA | Abrir um arquivo pode cumprir “ordem escondida” no nome. |
| 3 | CONFIG-SSH-PERMIT-ROOT | CONFIG | SELECIONADA | A chave mestra fica na porta da frente. |
| 4–6 | 3 CONFIG a escolher | CONFIG | AGUARDANDO | ver opcionais + extras |
| 7 | CVE-2024-6387 | CVE | SELECIONADA | A portaria pode se distrair no timeout (lab: atualizar pacote). |
| 8 | CVE-2024-48990 | CVE | SELECIONADA | O encarregado pega a caixa de ferramentas trocada. |
| 9 | CVE-2023-4911 | CVE | SELECIONADA | O “ajuste fino” longo demais troca quem dirige. |
| 10 | CVE-2024-12084 | CVE | SELECIONADA | A calculadora da mudança estoura o livro-caixa. |
| 11 | CVE-2025-48384 | CVE | SELECIONADA | As caixas vão ao depósito errado. |
| 12 | CVE-2024-11053 | CVE | SELECIONADA | A senha do banco A pode ir para o banco B. |
