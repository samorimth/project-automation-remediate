# Laboratório experimental do TCC

Uso da inteligência artificial generativa na geração e validação de scripts para remediação de vulnerabilidades em sistemas operacionais Linux.

Este diretório contém o laboratório do TCC. A CVE-2024-38428 foi executada em `us-east-2`. A pilha histórica foi destruída. A reexecução deixou ligados a VPC, o NAT e a AMI privada até `AUTORIZO_DESTRUIR_RECURSOS`.

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
- `OPENAI_API_KEY` / `OPENAI_MODEL` para `generate`, com saldo na organização OpenAI. O experimento usa `gpt-6-luna` com `reasoning_effort=none`. Sem créditos, a API responde `insufficient_quota` e nenhum script é gravado. <!-- pragma: allowlist secret -->

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
python -m src.main report
```

## Documentação

- [docs/ambiente.md](docs/ambiente.md)
- [docs/metodologia.md](docs/metodologia.md)
- [docs/execucao.md](docs/execucao.md)
- [docs/limitacoes.md](docs/limitacoes.md)
- [docs/resultados_tcc.md](docs/resultados_tcc.md)
- [docs/arquitetura/descricao_arquitetura.md](docs/arquitetura/descricao_arquitetura.md)
- [scenarios/README.md](scenarios/README.md)
- [docs/auditoria_inicial.md](docs/auditoria_inicial.md)
- [docs/auditoria_validador.md](docs/auditoria_validador.md)
- [docs/modelo_ia.md](docs/modelo_ia.md)
- [docs/linha_do_tempo.md](docs/linha_do_tempo.md)
- [docs/plano_reexecucao.md](docs/plano_reexecucao.md)
- [docs/levantamento_inicial_tcc.md](docs/levantamento_inicial_tcc.md)
- [docs/plano_13_15.md](docs/plano_13_15.md)
- [docs/reexecucao_resultado.md](docs/reexecucao_resultado.md)

A auditoria de 12 de novembro de 2026 preserva as evidências em `evidence_archive/historical-cve-2024-38428/` e separa tentativas de infraestrutura, chamadas à API e execuções. A reexecução de 12 de novembro de 2026 está em `docs/reexecucao_resultado.md`. As EC2 temporárias foram destruídas. A VPC, o NAT e a AMI privada continuam até `AUTORIZO_DESTRUIR_RECURSOS`.
