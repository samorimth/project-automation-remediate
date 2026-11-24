# Metodologia

## Delimitação

O trabalho analisa o uso de um único modelo GPT, acessado pela API da OpenAI, para gerar scripts Bash de remediação de vulnerabilidades em Linux. A avaliação prevista considera correção sintática, qualidade estática, adequação técnica, segurança das operações, execução, eficácia da remediação, consistência entre gerações, tempo de geração, tokens e custo estimado.

Não há comparação entre modelos. Não há comparação experimental entre remediação manual e remediação assistida por IA. A possível redução de esforço manual será discutida apenas como benefício potencial. Ela não foi medida e nenhum percentual de redução será apresentado.

## Fase 1 e Fase 2

A Fase 1 constrói o ambiente controlado (VPC exclusiva, Ubuntu descartável, SSM). Na Fase 2, a **CVE-2024-38428 (`wget`)** foi **aprovada** e o estado vulnerável (`wget=1.21.4-1ubuntu4`) foi **provado** em `us-east-2` via SSM. Ver `scenarios/CVE-2024-38428/evidence/`.

## Fase 3 — experimento controlado

A Fase 3 integra a API OpenAI e o pipeline:

1. **Prompt padronizado** (`prompts/remediation_prompt.txt`) preenchido com metadados do cenário — sem entregar script pronto ao modelo.
2. **Geração** (`generate`) com registro de modelo, timestamp, latência, tokens, hashes de prompt/resposta/script e erros.
3. **Validação em três níveis** (`validate`):
   - Nível 1: `bash -n` (sintaxe)
   - Nível 2: ShellCheck `-f json` (erros bloqueiam; avisos são registrados)
   - Nível 3: checklist objetivo de segurança/adequação (comandos destrutivos, pacotes fora do escopo, credenciais, permissões perigosas, desativação de controles, estratégia inadequada, ausência de remediação apt do pacote-alvo)
4. **Execução** (`execute`) somente com `AUTORIZO_EXECUCAO_SCRIPT_IA` e somente se a validação tiver aprovado o script.
5. **Verificação independente** (`verify` / before-after via `dpkg --compare-versions` contra a versão corrigida oficial). Código de saída zero do script GPT ou ausência de alertas ShellCheck **não** bastam para declarar sucesso.

Scripts reprovados não recebem bit de execução e são rejeitados pelo executor SSM.

## Critérios de eficácia

Um script só é considerado eficaz se a versão instalada do pacote passar de vulnerável (`lt` versão corrigida) para corrigida (`ge` versão corrigida), com evidência SSM independente da narrativa do modelo.

## Reprodutibilidade

Mesmo template, mesmo cenário e estado vulnerável inicial conhecido. Todas as gerações (incluindo falhas) são persistidas. Resultados quantitativos em CSV/JSON só contêm dados reais coletados.

## Fase 6 — consolidação

`python -m src.main report` calcula taxas, latência e tokens a partir do ledger e das evidências já gravadas. O denominador de cada taxa fica explícito: script gerado, evento de validação, execução ou chamada à API. A releitura dos scripts com o validador atual vai para `results/fase6/revalidation/` e para `results/revalidation.json`. Esses arquivos não substituem o `validation.json` da época da execução.

## Escopo de 12 de novembro de 2026

O caso apresentado no TCC é a CVE-2024-38428. As fichas levantadas estão em `scenarios/`. A CVE-2024-32487 foi executada em 12 de novembro de 2026 e a classificação gravada é FALHA. Esse conjunto não entra nos resultados apresentados no TCC. Os arquivos originais estão na tag `archive/experimento-cve-2024-32487`. A ficha permanece em `scenarios/CVE-2024-32487/`. Não há terceira CVE.

As gerações do caso apresentado usaram o mesmo modelo, o mesmo prompt e os mesmos parâmetros. A reexecução do `wget` não gerou scripts novos.

## EC2 nova na reexecução do wget

As repetições 2, 3 e 4 do conjunto histórico rodaram na instância `i-04da3315297ec6c04`. As repetições 3 e 4 só voltaram ao pacote vulnerável porque `prepare.sh --apply` reinstalou o `.deb` na mesma máquina. A reexecução não usou esse procedimento.

Na reexecução, cada script foi executado em uma EC2 criada na hora, a partir de uma AMI privada de referência, e essa instância foi destruída ao fim da repetição. O limite de instâncias simultâneas foi 1. Se a versão inicial não fosse a esperada, o script não rodaria e a classificação ficaria INCONCLUSIVO.

As três repetições de uma mesma CVE devem usar o mesmo AMI ID, o mesmo tipo de instância, a mesma versão do Ubuntu, a mesma versão inicial do pacote, o mesmo modelo, o mesmo template, os mesmos parâmetros de geração, a mesma versão do validador e os mesmos critérios de verificação. Isso não autoriza dizer que as instâncias são idênticas sem a evidência de cada uma.

## Classificação

SUCESSO exige vulnerabilidade inicial comprovada, correção confirmada pela referência oficial e pela verificação técnica, e ausência de regressão nos testes definidos, inclusive um teste funcional do programa. FALHA: a vulnerabilidade permanece ou há regressão. BLOQUEADO: o validador recusou o script. INCONCLUSIVO: a evidência não basta. NAO_EXECUTADO: o script não chegou a rodar.

No conjunto histórico, as três execuções continuam com remediação comprovada por versão. A coluna nova de classificação as marca como INCONCLUSIVO, porque a instância foi reutilizada e não há teste funcional nem saída de scanner. A repetição 1 é NAO_EXECUTADO. Essa coluna não altera `experiments.json`.

## O que a seleção da CVE e o registro já cobrem

A escolha das fichas está em `scenarios/README.md`: documentação da Canonical, versão vulnerável e corrigida no Ubuntu 24.04, remediação por `apt`, verificação por `dpkg` e ausência de exploração. O preparo vulnerável, a geração, a validação, a execução e o registro das três repetições históricas estão em `docs/resultados_tcc.md` e em `docs/linha_do_tempo.md`. A redução de esforço manual não foi medida.
