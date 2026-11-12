# Levantamento inicial do laboratório

Texto de apoio à pré-banca de 16 de novembro de 2026. Os números abaixo vêm de arquivos já gravados. O que ainda não foi feito está marcado como planejado.

## 1. Objetivo

O laboratório observa se um modelo GPT, chamado pela API da OpenAI, consegue gerar scripts Bash que atualizam um pacote vulnerável no Ubuntu. O script passa por uma validação estática antes de rodar. A correção é conferida por comandos independentes do texto produzido pelo modelo.

O escopo desta etapa são duas CVEs reais. A primeira já tem resultados. A segunda está proposta e ainda não foi aprovada. Não há uma terceira CVE neste momento.

## 2. Por que estas CVEs

A CVE-2024-38428 foi escolhida porque a Canonical documenta o pacote `wget` no Ubuntu 24.04, a correção é uma atualização por `apt` e a prova pode ser a versão instalada, sem explorar a falha. O Ubuntu CVE Tracker e o JSON da USN-6852-1, lidos em 12 de novembro de 2026, indicam correção a partir de `1.21.4-1ubuntu4.1`. A página HTML dessa USN não foi lida: a consulta devolveu HTTP 503.

A segunda candidata é a CVE-2024-32487, no pacote `less`. Em 12 de novembro de 2026, o Ubuntu CVE Tracker mostrou prioridade Medium e correção `590-2ubuntu2.1` no Ubuntu 24.04. O OSV da USN-6756-1 lista `590-2ubuntu2` entre as versões afetadas e informa que a correção no Ubuntu 24.04 não depende do Ubuntu Pro. O arquivo `less_590-2ubuntu2_amd64.deb` está no archive.ubuntu.com, com SHA-256 `e8560662fbf944dd4a4348faa0d8b4652fbc24939e6fe4ac06c0bdf946f9f935`. A página HTML da USN-6756-1 também devolveu HTTP 503. Essa CVE só entra no experimento depois de aprovação. A ficha está em `scenarios/CVE-2024-32487/scenario.md`.

As duas CVEs usam pacotes diferentes, remediação por atualização e verificação por `dpkg`. Nenhuma das duas exige um teste de exploração.

## 3. Ambiente

O laboratório usa Ubuntu 24.04 em EC2 privada na região `us-east-2`, sem SSH e sem IP público. O acesso é o AWS Systems Manager. A saída para a internet passa por um NAT Gateway, necessário para o agente SSM e para o `apt`.

No conjunto histórico, as três execuções do `wget` compartilharam a instância `i-04da3315297ec6c04`, criada da AMI pública `ami-096d6538c463eb1db`. As repetições 3 e 4 restauraram o pacote vulnerável com `prepare.sh --apply` nessa mesma máquina. Essa pilha foi destruída depois do experimento.

Na reexecução de 12 de novembro, a AMI privada `ami-03629c5c47c71759b` guardou o `wget` `1.21.4-1ubuntu4`. Cada script rodou em uma EC2 nova dessa imagem. Essas EC2 foram destruídas. A VPC `vpc-07ed5b7db90bfd3a6`, o NAT `nat-07030ea6ff070f9d0` e a AMI continuam ligados.

## 4. Tecnologias

Python, Terraform, AWS EC2, Systems Manager, Bash, ShellCheck e a API da OpenAI. Os relatórios saem em CSV, JSON e gráficos PNG. O comando `python -m src.main report` lê as evidências já gravadas e não chama a AWS nem a OpenAI.

## 5. Geração dos scripts

O prompt está em `prompts/remediation_prompt.txt`. Ele recebe os dados do cenário e não entrega um script pronto. Cada chamada grava modelo, latência, tokens e hashes. Uma chamada que falha não conta como script gerado.

Para o `wget` houve quatro chamadas à API e uma tentativa local anterior, às 07:40 (horário de Brasília), em que a chave estava ausente e nenhuma chamada ocorreu. A repetição 1, às 07:44, pediu `gpt-4.1` e recebeu HTTP 429, sem script e sem tokens. As repetições 2, 3 e 4 gravaram no metadado o identificador `gpt-6-luna`, com `reasoning_effort=none` e zero tokens de raciocínio. O cliente não guarda, em campos separados, o modelo enviado e o modelo devolvido. Não há identificador da resposta da API. <!-- pragma: allowlist secret -->

Não haverá novas chamadas à API enquanto essa etapa de documentação estiver em curso.

## 6. Validação

O validador tem três níveis: `bash -n`, ShellCheck e um checklist de comandos perigosos, pacotes fora do escopo, credenciais e ausência de atualização do pacote alvo. A aprovação não significa segurança absoluta. O checklist não é um interpretador de shell.

Na repetição 2 do `wget`, a primeira passagem reprovou o script porque tratou `$PACKAGE` e `||` como pacotes fora do escopo. O código foi corrigido e a segunda passagem aprovou o mesmo arquivo. O `validation.json` da primeira passagem foi sobrescrito. A reprovação permanece no ledger. A releitura atual dos três scripts, sem alterar os bytes, também os aprovou. O registro está em `docs/auditoria_validador.md`.

## 7. Métricas

As taxas usam denominadores diferentes. Elas estão em `results/summary.csv` e nos gráficos `results/charts/syntax_success.png`, `remediation_success.png`, `security_approval.png`, `generation_time.png`, `token_usage.png` e `cost.png`.

| Métrica, conjunto histórico | Numerador / denominador |
| --- | --- |
| Sintaxe entre scripts gerados | 3 / 3 |
| ShellCheck sem erro bloqueante | 3 / 3 |
| Aprovação de segurança entre eventos do ledger | 3 / 4 |
| Remediação comprovada por versão entre execuções | 3 / 3 |
| Remediação entre chamadas à API | 3 / 4 |

A chamada HTTP 429 entra como falha de API e não entra no custo, porque não devolveu tokens. As três respostas somam cerca de US$ 0,001 pela tabela pública de US$ 0,10 por milhão de tokens de entrada e US$ 0,50 por milhão de saída. Isso não é fatura.

Pelo protocolo novo, as três execuções históricas são INCONCLUSIVO: a mesma EC2 foi reutilizada e não houve teste funcional. O booleano de remediação por versão permanece 1. A repetição 1 é NAO_EXECUTADO. Essas colunas estão em `results/experimental_runs.csv` e não reescrevem `experiments.json`.

## 8. Resultados já obtidos

No conjunto histórico, o `wget` passou de `1.21.4-1ubuntu4` para `1.21.4-1ubuntu4.5` nas três execuções SSM com status `Success`.

Na reexecução, o mesmo salto de versão ocorreu em seis instâncias novas da AMI privada: três na sonda `file://` e três no teste HTTP local. O `wget` deste Ubuntu recusa `file://` com a mensagem `Unsupported scheme`, tanto antes quanto depois da atualização. Por isso o conjunto da sonda ficou classificado como FALHA da sonda. No conjunto HTTP, `wget` contra `http://127.0.0.1:9876/lab` devolveu o texto `tcc-lab-wget-ok` com código 0, antes e depois. A classificação desse conjunto é SUCESSO nas três repetições. Os identificadores estão em `docs/reexecucao_resultado.md`. Esses resultados não foram somados às taxas históricas.

## 9. Limitações

A redução de esforço manual não foi medida. Não há comparação entre modelos. As taxas de 3/3 descrevem o `wget`, não outras CVEs. A página HTML das USN citadas não foi lida. As tentativas de infraestrutura 1 a 3 existem só na narrativa de `STATUS.md`. O scanner de CVE não estava instalado, e a ausência de alerta não foi usada como prova. A frase da USN-8543-2 que restringe a CVE-2024-38428 ao Ubuntu 14.04 não substitui o tracker nem o OSV.

## 10. Próximas etapas

A segunda CVE só começa depois da aprovação e de nova autorização para recursos pagos e, se houver geração, para a API. O plano dos dias 13, 14 e 15 de novembro está em `docs/plano_13_15.md`. A destruição da VPC, do NAT e da AMI privada que ainda estão ligados pede a frase `AUTORIZO_DESTRUIR_RECURSOS`.
