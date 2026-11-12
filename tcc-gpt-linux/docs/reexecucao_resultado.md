# Reexecução controlada em 12 de novembro de 2026

Horários em America/Sao_Paulo (UTC−3). Autorização recebida: `AUTORIZO_RECURSOS_PAGOS` e `AUTORIZO_EXECUCAO_SCRIPT_IA`. Não houve chamada à API da OpenAI. Os scripts em `generated_scripts/` não foram editados.

## AMI de referência

| Campo | Valor |
| --- | --- |
| AMI | `ami-03629c5c47c71759b`, privada, criação 11:53 |
| Base | AMI pública `ami-096d6538c463eb1db` |
| Instância auxiliar | `i-0361f8d18abe59e1c`, destruída depois da imagem |
| Ubuntu observado | 24.04.5 LTS, noble |
| Pacote antes da imagem | `wget 1.21.4-1ubuntu4`, menor que `1.21.4-1ubuntu4.1` |
| SHA-256 do `.deb` | `1d078bf2a22c2c6da84788818ebf055a10f5f6b5ea629f1dd0dd11660b51def6` |

`prepare.sh --apply` rodou só nessa instância auxiliar, que não executou script de remediação.

## Conjunto que atende o teste funcional

Mesma AMI. Servidor HTTP apenas em `127.0.0.1:9876`. Três `instance_id` diferentes. Cada instância executou um único script e foi destruída.

| Repetição | Instância | Antes | Depois | HTTP local | Limpeza | Classificação |
| --- | --- | --- | --- | --- | --- | --- |
| 2 | `i-0fcb8ab88a727b409` | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.5` | código 0, corpo `tcc-lab-wget-ok` | 12:19 | SUCESSO |
| 3 | `i-0ab458c87a79d078b` | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.5` | código 0, corpo `tcc-lab-wget-ok` | 12:21 | SUCESSO |
| 4 | `i-0a086264652dd0b86` | `1.21.4-1ubuntu4` | `1.21.4-1ubuntu4.5` | código 0, corpo `tcc-lab-wget-ok` | 12:24 | SUCESSO |

`file://` falhou com `Unsupported scheme` antes e depois, nas três. Essa falha também é a classificação gravada do primeiro conjunto, em `results/reexecution/CVE-2024-38428/`, cujas instâncias foram `i-0f4cd4e8ed81eb263`, `i-0553b8cad05d9a487` e `i-04bab8319ea0dd9a3`. A versão também subiu nas três. A leitura dos dois conjuntos está em `results/reexecution/LEITURA.md`.

Nenhuma dessas instâncias é a instância histórica `i-04da3315297ec6c04`.

## O que continua ligado

As EC2 temporárias foram destruídas. Continuam a VPC `vpc-07ed5b7db90bfd3a6`, o NAT `nat-07030ea6ff070f9d0` e a AMI privada. A destruição dessa infraestrutura compartilhada e da AMI pede `AUTORIZO_DESTRUIR_RECURSOS`. Enquanto o NAT permanecer ligado, o preço já citado em `docs/ambiente.md` é cerca de US$ 0,045 por hora, mais o endereço público.

Scanner de CVE não estava instalado. A ausência de alerta não foi usada como prova.
