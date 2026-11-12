# Laboratório experimental do TCC

Uso da inteligência artificial generativa na geração e validação de scripts para remediação de vulnerabilidades em sistemas operacionais Linux.

Este diretório contém o laboratório do TCC. Fases 1–2 concluídas (infra + CVE-2024-38428 aprovada com estado vulnerável provado em `us-east-2`, instância `i-04da3315297ec6c04`). A **Fase 3** implementa geração via OpenAI, validação em três níveis e execução SSM condicionada a autorização explícita.

**Recursos pagos ativos** (NAT + EC2) até cleanup autorizado.

## O que a Fase 3 entrega

- Template de prompt (`prompts/remediation_prompt.txt`) e `scenario.json` da CVE.
- Cliente OpenAI com telemetria (modelo, latência, tokens, hashes) sem logar a API key.
- Validador: `bash -n` + ShellCheck + checklist de segurança/adequação.
- Executor SSM que exige `AUTORIZO_EXECUCAO_SCRIPT_IA` e script previamente aprovado.
- Verificação independente de versão do pacote (`verify`).
- Persistência mínima de métricas reais em `results/`.

## Pré-requisitos locais

- Python 3.11 ou superior.
- Terraform 1.6 ou superior.
- `shellcheck` no PATH (validação Nível 2).
- `OPENAI_API_KEY` / `OPENAI_MODEL` para `generate`.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m src.main check
pytest
```

## Comandos principais

```bash
python -m src.main provision --authorize AUTORIZO_RECURSOS_PAGOS
python -m src.main generate --cve CVE-2024-38428
python -m src.main validate --cve CVE-2024-38428
python -m src.main execute --cve CVE-2024-38428 --authorize AUTORIZO_EXECUCAO_SCRIPT_IA
python -m src.main verify --cve CVE-2024-38428
python -m src.main cleanup --authorize AUTORIZO_DESTRUIR_RECURSOS
```

## Documentação

- [docs/ambiente.md](docs/ambiente.md)
- [docs/metodologia.md](docs/metodologia.md)
- [docs/execucao.md](docs/execucao.md)
- [docs/limitacoes.md](docs/limitacoes.md)
- [docs/resultados_tcc.md](docs/resultados_tcc.md)
- [docs/arquitetura/descricao_arquitetura.md](docs/arquitetura/descricao_arquitetura.md)
- [scenarios/README.md](scenarios/README.md)
