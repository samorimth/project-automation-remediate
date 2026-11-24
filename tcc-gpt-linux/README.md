# Laboratório experimental do TCC

Uso da inteligência artificial generativa na geração e validação de scripts para remediação de vulnerabilidades em sistemas operacionais Linux.

O caso apresentado no TCC é a CVE-2024-38428 (`wget`), executada em `us-east-2`. A contextualização, a arquitetura e as limitações estão no [README da raiz do repositório](../README.md). A figura do TCC está em [docs/arquitetura/figura-projeto-tcc.png](docs/arquitetura/figura-projeto-tcc.png).

A CVE-2024-32487 (`less`) também foi executada em 12 de novembro de 2026. Os três scripts falharam no Systems Manager e a classificação gravada é FALHA. Esse experimento não integra os resultados apresentados na versão atual do TCC. Os arquivos originais estão na tag `archive/experimento-cve-2024-32487`, no commit `4cb0d28`. A ficha permanece em [scenarios/CVE-2024-32487/](scenarios/CVE-2024-32487/). As demais fichas de candidatos continuam em [scenarios/](scenarios/).

As pilhas, os NAT Gateways e as AMIs privadas foram destruídos depois da coleta.

## O que o laboratório faz

- Monta o prompt a partir de [prompts/remediation_prompt.txt](prompts/remediation_prompt.txt) e do `scenario.json` da CVE.
- Consulta a API da OpenAI e grava modelo, latência, tokens e hashes, sem registrar a chave.
- Valida o script com `bash -n`, ShellCheck e um checklist. Erro do ShellCheck reprova; aviso e informação não reprovam.
- Executa pelo Systems Manager somente o script aprovado e somente com a frase `AUTORIZO_EXECUCAO_SCRIPT_IA`.
- Confere a versão do pacote com `dpkg`, fora do texto do modelo.
- Grava as métricas em [results/](results/).

O campo `model` dos metadados é um único identificador. O padrão `gpt-4o-mini` de [src/config.py](src/config.py) vale quando a variável de ambiente não define o modelo. Ele não é o identificador gravado nas três gerações que produziram script. A repetição 1 pediu `gpt-4.1`, recebeu HTTP 429 e não gerou script. O cliente não separa o modelo pedido do modelo devolvido.

## Pré-requisitos locais

- Python 3.11 ou superior.
- Terraform 1.6 ou superior.
- `shellcheck` no PATH, para a validação de nível 2.
- `OPENAI_API_KEY` e, se for o caso, `OPENAI_MODEL`, apenas para `generate`. Sem saldo, a API não grava script.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m src.main check
pytest
```

`check` e `pytest` não acessam a AWS nem a OpenAI.

## Comandos

```bash
python -m src.main provision --authorize AUTORIZO_RECURSOS_PAGOS
python -m src.main generate --cve CVE-2024-38428
python -m src.main validate --cve CVE-2024-38428
python -m src.main execute --cve CVE-2024-38428 --authorize AUTORIZO_EXECUCAO_SCRIPT_IA
python -m src.main verify --cve CVE-2024-38428
python -m src.main cleanup --authorize AUTORIZO_DESTRUIR_RECURSOS
python -m src.main report
```

`provision`, `execute` e `cleanup` criam, executam ou destroem recursos pagos. `report` só relê evidências já gravadas.

## Onde estão as evidências do wget

- Conjunto histórico: [generated_scripts/CVE-2024-38428/](generated_scripts/CVE-2024-38428/) e [results/experiments.json](results/experiments.json). `verify_independent.json` existe na repetição 2 e não existe nas repetições 3 e 4.
- Reexecução com `file://`, classificada como FALHA: [results/reexecution/CVE-2024-38428/](results/reexecution/CVE-2024-38428/).
- Reexecução HTTP, classificada como SUCESSO: [results/reexecution/CVE-2024-38428-http/](results/reexecution/CVE-2024-38428-http/).
- Cópia congelada: [evidence_archive/historical-cve-2024-38428/](evidence_archive/historical-cve-2024-38428/).

Os commits desse material no histórico são `82b6270`, `a182465` e `d7b95f9`.

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
- [docs/reexecucao_resultado.md](docs/reexecucao_resultado.md)
