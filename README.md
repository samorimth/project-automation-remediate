# Remediação assistida por IA

Protótipo de laboratório para o trabalho de conclusão de curso sobre o uso de inteligência artificial generativa na remediação de vulnerabilidades em Linux. A aplicação registra findings, scripts, aprovações e evidências para comparar o trabalho manual com o trabalho assistido. Ela não conclui, por si, que a IA reduz tempo ou melhora a qualidade: esses resultados serão medidos.

## Fase 1

Esta versão entrega a estrutura do backend:

- API FastAPI com `GET /health`.
- Configuração por variáveis de ambiente.
- SQLite com o esquema do laboratório.
- Máquina de estados da remediação e invalidação da aprovação quando o SHA-256 do script muda.
- Autenticação de laboratório pronta (`X-API-Key`), ainda sem rotas de negócio protegidas.
- Testes automatizados.

Ainda não há API simulada de vulnerabilidades, Terraform, AWS, scanner, provedor de IA, GitLab nem executor. Nenhum endpoint executa comandos.

## Arquitetura prevista

O backend roda na máquina do pesquisador. Uma instância Ubuntu 24.04, criada depois com Terraform, será o único alvo. A API principal conversa com fontes externas apenas por interfaces: vulnerabilidades, IA, GitLab e execução via AWS Systems Manager. A validação posterior é independente do código de saída do script.

Estados da remediação: `GENERATED → REVIEWED → APPROVED → PUBLISHED → EXECUTED → VALIDATED`. Também existem `REJECTED` e `FAILED`. `DETECTED` é o estado do finding, antes de existir uma remediação. Transições fora dessa ordem são rejeitadas. Mudar o script antes da execução devolve o registro a `GENERATED` e invalida a aprovação.

## Requisitos

- Python 3.12
- Nenhuma conta de nuvem nesta fase

## Instalação

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

Defina `LAB_API_KEY` no arquivo `.env`. Esse arquivo não deve ser versionado. A chave ainda não protege `/health`; as próximas rotas de negócio vão exigi-la.

## Execução

```bash
uvicorn remediation.main:app --reload
```

A documentação interativa fica em `http://127.0.0.1:8000/docs`. O banco padrão é `data/remediation.db`, criado na subida da aplicação.

Verificação local:

```bash
curl http://127.0.0.1:8000/health
```

Resposta esperada:

```json
{"status":"ok","version":"0.1.0","database":"ok"}
```

## Testes e análise estática

```bash
pytest
ruff check src tests
ruff format --check src tests
```

## Persistência

O SQLite guarda findings, experimentos, remediações, aprovações, execuções, validações e a lista de instâncias autorizadas. Os tempos manuais do pesquisador são campos do experimento, preenchidos por ele; o sistema não observa a elaboração manual. `create_all` cria o esquema neste protótipo. Alembic entra apenas se uma fase futura precisar migrar dados já coletados.

## Limites conhecidos

- Não existe geração, revisão HTTP, publicação, execução nem validação de vulnerabilidade.
- A análise estática de scripts Bash ainda não foi implementada. A máquina de estados também não a substitui.
- A aprovação só é considerada vigente quando o estado já passou por `APPROVED` e o hash aprovado é idêntico ao hash do script atual.
- Um script já executado, validado, rejeitado ou falho não pode ser alterado no mesmo registro. Uma nova tentativa será outro registro.
