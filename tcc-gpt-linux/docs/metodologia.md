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

`python -m src.main report` calcula taxas, latência e tokens a partir do ledger e das evidências já gravadas. O denominador de cada taxa fica explícito: script gerado, evento de validação, execução ou chamada à API. A releitura dos scripts com o validador atual vai para `results/fase6/revalidation/` e não substitui o `validation.json` da época da execução.
