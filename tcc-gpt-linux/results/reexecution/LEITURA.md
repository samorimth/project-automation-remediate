# Leitura dos dois conjuntos da reexecução

Há dois conjuntos. Eles não entram no ledger histórico `results/experiments.json`.

## Conjunto file://

Pasta: `results/reexecution/CVE-2024-38428/`.

Três EC2 novas, AMI `ami-03629c5c47c71759b`, scripts originais sem alteração. A versão passou de `1.21.4-1ubuntu4` para `1.21.4-1ubuntu4.5` nas três, com SSM `Success`. A classificação gravada é FALHA porque a sonda `wget file:///etc/os-release` devolveu `Unsupported scheme` e zero bytes. O mesmo binário respondeu `GNU Wget 1.21.4 built on linux-gnu.`

## Conjunto HTTP local

Pasta: `results/reexecution/CVE-2024-38428-http/`.

Outras três EC2, a mesma AMI, os mesmos scripts. Antes e depois da execução, `file://` continuou com `file_exit=1`. O teste `http://127.0.0.1:9876/lab`, servido só na própria instância, devolveu `tcc-lab-wget-ok` com código 0 tanto no estado vulnerável quanto depois da atualização. A classificação deste conjunto é SUCESSO nas três repetições.

A FALHA do primeiro conjunto descreve a sonda `file://`, que este wget do Ubuntu 24.04 não implementa. Não descreve permanência da versão vulnerável.
