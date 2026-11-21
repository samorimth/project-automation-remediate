# Descrições não técnicas — portfólio de 10 labs

Texto em português, acessível a leitores não técnicos (banca / TCC).  
Cada lab traz: o **problema** em poucas palavras, um **exemplo prático** do cotidiano (analogia — sem passo a passo de ataque) e a **correção** esperada.

**CVE** = falha em software (corrige-se atualizando o pacote).  
**CONFIG** = configuração ou permissão mal ajustada no sistema (corrige-se mudando a configuração — **não é CVE**).

O laboratório **não** reproduz exploração ativa; a prova técnica é versão de pacote (CVE) ou inspeção de configuração/permissões (CONFIG). Detalhes técnicos: [`PORTFOLIO_10_LABS.md`](PORTFOLIO_10_LABS.md) e `scenarios/<id>/scenario.md`.

---

## 1. CVE-2024-38428 — `wget` (CVE)

**Problema.** O programa `wget` (usado para baixar arquivos da internet) interpreta mal certos endereços: o que deveria ser só “login” do endereço pode ser lido como o nome do servidor, e a ferramenta pode conectar-se a um destino diferente do pretendido.

**Exemplo prático.** Imagine que você pede a um mensageiro para entregar uma carta no banco da sua cidade, mas o endereço veio escrito de forma confusa — com um detalhe no meio do texto que parece outro número de rua. O mensageiro, sem perceber, leva a carta para outro prédio. Você achava que falava com o banco; na verdade falava com um estranho. Sem a correção, um endereço “mal escrito” de propósito pode redirecionar o download para o lugar errado.

**Correção.** Atualizar o pacote `wget` para a versão corrigida publicada pela Canonical (USN-6852-1), de modo que o endereço seja interpretado corretamente.

---

## 2. CVE-2024-32487 — `less` (CVE)

**Problema.** O visualizador de texto `less` trata mal nomes de arquivo que contêm quebras de linha; em certas condições, abrir um arquivo com nome “armadilha” pode fazer o sistema executar comandos que o usuário não pediu.

**Exemplo prático.** Pense em uma pasta de documentos em que cada arquivo tem um rótulo na capa. Alguém cola um rótulo com duas linhas: na primeira, o título inocente (“relatório”); na segunda, uma ordem escondida (“abra também o cofre”). Quando a secretária só queria folhear o relatório, o sistema “lê” as duas linhas e cumpre a ordem extra. Sem a correção, um nome de arquivo enganoso pode virar uma instrução indesejada.

**Correção.** Atualizar o pacote `less` para a versão corrigida (USN-6756-1), para que nomes especiais não sejam interpretados como comandos.

---

## 3. CONFIG-SSH-PERMIT-ROOT — login root via SSH (CONFIG)

**Problema.** O servidor de acesso remoto (SSH) está configurado para permitir que a conta **root** (o “administrador total” do sistema) entre com senha. Isso **não é uma falha de software catalogada como CVE** — é uma **configuração** permissiva demais.

**Exemplo prático.** É como deixar a chave mestra do prédio na fechadura da porta da frente, com um cartaz “pode entrar quem souber a senha do síndico”. Qualquer um que descubra ou chute essa senha ganha controle de tudo: apartamentos, arquivos, luzes. Em boas práticas, a chave mestra não se usa assim; entra-se com identidade individual e, se preciso, com chave especial (não senha simples).

**Correção.** Ajustar `PermitRootLogin` para `prohibit-password` ou `no` (hardening típico), e recarregar o SSH — sem precisar “corrigir um bug” de pacote.

---

## 4. CONFIG-WORLD-WRITABLE-SENSITIVE — segredo world-writable (CONFIG)

**Problema.** Um arquivo sensível do laboratório (token/senha de exemplo) está com permissão de escrita para **qualquer usuário** da máquina (`0666`). De novo: **CONFIG**, não CVE — o problema é quem pode ler/alterar o arquivo.

**Exemplo prático.** Imagine um caderno com a senha do Wi‑Fi (ou o PIN do cofre) deixado aberto na mesa da sala de espera, e ainda com uma caneta ao lado: qualquer visitante pode ler **e** trocar o que está escrito. Em casa, você guardaria esse caderno na gaveta trancada; no servidor, o equivalente é restringir quem lê e quem escreve.

**Correção.** Restringir o arquivo a dono `root` e modo `0600` (só o administrador lê/escreve), como se trancasse o caderno na gaveta.

---

## 5. CONFIG-CRON-WEAK-PERMS — job cron com permissão fraca (CONFIG)

**Problema.** Um agendamento automático (`cron`) — a “lista de tarefas diárias do sistema” — foi criado com permissão de escrita para todos. Qualquer usuário local poderia alterar o que o sistema fará no horário marcado. **CONFIG**, não CVE.

**Exemplo prático.** É a agenda da empresa afixada no mural do corredor, com espaço em branco e caneta livre: “toda manhã, pagar as contas”. Um estranho pode riscar e escrever “toda manhã, transferir o caixa para outra conta”. O relógio continua batendo; a tarefa muda. Sem permissões corretas, o “piloto automático” do sistema deixa de ser confiável.

**Correção.** Deixar o arquivo do job só legível (ex.: `0644`) e de propriedade do administrador (`root:root`), para que ninguém altere a agenda sem autorização.

---

## 6. CONFIG-LOCAL-HTTP-BIND — serviço escutando em todas as interfaces (CONFIG)

**Problema.** Um serviço HTTP de laboratório escuta em **todas** as interfaces da máquina (`0.0.0.0`), em vez de só no “interior” (`127.0.0.1`). **CONFIG** de superfície de ataque — não é CVE de pacote.

**Exemplo prático.** Pense em um interfone do condomínio: o correto é atender só quem está na portaria do seu prédio. Deixar o serviço em `0.0.0.0` é como ligar o interfone também para a rua e para o prédio vizinho — qualquer um na rede local pode “tocar a campainha”. No lab a máquina não está na internet pública, mas a configuração ainda ensina o risco: serviço administrativo não deve ficar “visível” além do necessário.

**Correção.** Reconfigurar o bind para `127.0.0.1` (só a própria máquina) ou desligar o serviço, reduzindo a superfície exposta.

---

## 7. CVE-2024-11053 — `curl` e vazamento de senha em redirecionamento (CVE)

**Problema.** O cliente `curl`, ao usar senhas guardadas em um arquivo de credenciais (`.netrc`) e seguir um redirecionamento HTTP, pode, em certos casos, enviar a senha do primeiro site para o segundo site.

**Exemplo prático.** Você entrega ao carteiro o envelope com a senha do banco A, pedindo para ir só ao banco A. No caminho, alguém coloca um aviso na porta: “esta agência mudou — vá ao banco B”. O carteiro, sem perceber o risco, leva o **mesmo envelope com a senha** para o banco B. Você só queria autenticar no A; o B acaba vendo o segredo. Sem a correção, um redirecionamento malicioso pode “carregar” a senha para o destino errado.

**Correção.** Atualizar `curl` / `libcurl` para a versão corrigida (USN-7162-1), para que a senha não acompanhe redirecionamentos indevidos.

---

## 8. CVE-2024-5742 — `nano` e arquivo de emergência inseguro (CVE)

**Problema.** Se o editor `nano` for interrompido no meio da edição, pode gravar um arquivo de emergência com permissões inadequadas; em cenários raros (por exemplo com `nano` rodando como administrador), isso abre janela para abuso via arquivo temporário.

**Exemplo prático.** Imagine um gerente ditando um documento confidencial na sala dele. No meio da frase, a luz cai e o rascunho de emergência é deixado na mesa da **sala comum**, onde qualquer funcionário pode mexer ou trocar o papel por um falso. Quem depois “retoma” a edição pode acabar confiando nesse rascunho errado. A correção é o editor guardar o rascunho de forma segura, sem deixar a “mesa comum” aberta.

**Correção.** Atualizar o pacote `nano` para a versão corrigida (USN-7064-1), endurecendo o tratamento do arquivo de emergência.

---

## 9. CVE-2025-1372 — `elfutils` / `eu-readelf` e arquivo malicioso (CVE)

**Problema.** A ferramenta `eu-readelf` (inspeciona arquivos de programa) pode falhar ou travar ao processar um arquivo especialmente preparado — risco local de negação de serviço (o programa “quebra”), sem o lab exigir exploração.

**Exemplo prático.** É como um scanner de bagagem no aeroporto que, diante de uma mala montada de propósito para confundir o sensor, trava a esteira inteira. Ninguém “roubou o avião”; o prejuízo é o serviço parar. Se um técnico ou um script automático inspecionar um arquivo “estragado de propósito”, a ferramenta pode cair e interromper o trabalho.

**Correção.** Atualizar `elfutils` (e bibliotecas correlatas) para a versão corrigida (USN-7369-1), para que entradas inválidas não derrubem a ferramenta.

---

## 10. CVE-2025-48384 — `git` e truque de caminho / submódulo (CVE)

**Problema.** O Git trata mal certos caracteres especiais (fim de linha) em caminhos de configuração e submódulo: o checkout pode ir para um lugar diferente do esperado e, em combinação com outros truques, pode acabar executando código sem a intenção do usuário.

**Exemplo prático.** Você pede à mudança que leve as caixas para o “depósito 3”. No rótulo, alguém cola um detalhe quase invisível que faz a mudança ler “depósito 3” e, na prática, entregar no **depósito 8** — onde já há um bilhete pedindo para “ligar o motor ao chegar”. Você achava que só estava organizando pastas; o sistema acabou seguindo um caminho e uma ordem que você não escolheu. Sem a correção, um repositório/submódulo enganoso pode desviar o destino dos arquivos.

**Correção.** Atualizar o pacote `git` para a versão corrigida (USN-7626-1), com tratamento seguro de caminhos e configuração.

---

## Resumo rápido (CVE × CONFIG)

| # | ID | Tipo | Em uma frase, se não corrigir… |
| --- | --- | --- | --- |
| 1 | CVE-2024-38428 | CVE | O download pode ir ao “prédio errado”. |
| 2 | CVE-2024-32487 | CVE | Abrir um arquivo pode cumprir uma “ordem escondida” no nome. |
| 3 | CONFIG-SSH-PERMIT-ROOT | CONFIG | A chave mestra fica na porta da frente. |
| 4 | CONFIG-WORLD-WRITABLE-SENSITIVE | CONFIG | O caderno de senhas fica na mesa da sala. |
| 5 | CONFIG-CRON-WEAK-PERMS | CONFIG | Qualquer um pode riscar a agenda automática. |
| 6 | CONFIG-LOCAL-HTTP-BIND | CONFIG | O interfone atende também a rua. |
| 7 | CVE-2024-11053 | CVE | A senha do banco A pode ir parar no banco B. |
| 8 | CVE-2024-5742 | CVE | O rascunho de emergência fica na “mesa comum”. |
| 9 | CVE-2025-1372 | CVE | Um arquivo “estragado” pode travar a inspeção. |
| 10 | CVE-2025-48384 | CVE | As caixas podem ir ao depósito errado (e acionar algo). |
