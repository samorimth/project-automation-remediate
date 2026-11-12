# Resultado da CVE-2024-32487

Experimento executado em 12 de novembro de 2026, depois da aprovação da segunda CVE. Os horários abaixo estão em Brasília (UTC−3). As evidências estão em `results/reexecution/CVE-2024-32487/` e os scripts em `generated_scripts/CVE-2024-32487/`. Este conjunto não entra nas taxas de `results/summary.csv`.

## O que foi conferido antes da AMI

O Ubuntu CVE Tracker e o OSV da USN-6756-1 foram lidos de novo neste dia. Para o Ubuntu 24.04, a correção mínima continua `590-2ubuntu2.1` e `590-2ubuntu2` continua entre as versões afetadas. O arquivo `less_590-2ubuntu2_amd64.deb` do archive.ubuntu.com teve SHA-256 `e8560662fbf944dd4a4348faa0d8b4652fbc24939e6fe4ac06c0bdf946f9f935`. A página HTML da USN-6756-1 devolveu HTTP 503.

## Geração

Três chamadas usaram o mesmo prompt, o mesmo modelo gravado no metadado e `reasoning_effort=none`. O cliente não separa o modelo enviado do modelo devolvido. Não houve HTTP 429.

| Repetição | Latência | Tokens de entrada | Tokens de saída | Custo estimado |
| --- | --- | --- | --- | --- |
| 1 | 7,8 s | 587 | 712 | US$ 0,000415 |
| 2 | 8,0 s | 587 | 940 | US$ 0,000529 |
| 3 | 7,8 s | 587 | 836 | US$ 0,000477 |

A soma estimada é cerca de US$ 0,0014, pela tabela pública de US$ 0,10 por milhão de tokens de entrada e US$ 0,50 por milhão de saída. Não é fatura. Os três arquivos passaram em `bash -n`, ShellCheck e no checklist. A validação estática não executa o script.

## Instâncias

A AMI privada `ami-0c49cb4a0e4553411` foi criada às 13:51 a partir da AMI pública `ami-096d6538c463eb1db`. Na imagem, o Ubuntu era 24.04.5 LTS e o `less` estava em `590-2ubuntu2`, abaixo de `590-2ubuntu2.1`. O `apt-cache policy` da instância auxiliar mostrou o candidato `590-2ubuntu2.1` em `noble-updates` e `noble-security`. O teste funcional, `less` lendo um arquivo local com o texto `tcc-lab-less-ok`, passou antes da criação da imagem.

Cada script rodou em uma EC2 nova dessa AMI. Nenhuma instância foi reutilizada. O teste funcional passou antes e depois da execução, porque a versão do pacote não mudou.

| Repetição | Instância | Versão inicial | Versão final | SSM | Código | Classificação |
| --- | --- | --- | --- | --- | --- | --- |
| rep01 | `i-01b00563ecbdf23d0` | `590-2ubuntu2` | `590-2ubuntu2` | Failed | 141 | FALHA |
| rep02 | `i-08a3b33b1cb3ba1db` | `590-2ubuntu2` | `590-2ubuntu2` | Failed | 141 | FALHA |
| rep03 | `i-0bff228c075537319` | `590-2ubuntu2` | `590-2ubuntu2` | Failed | 141 | FALHA |

Os comandos SSM foram `7ada333b-e969-4f1f-afaa-124b620abaa0`, `2ecbd937-2100-4b6a-ad71-f133a733065c` e `2524118f-c44f-4173-a6b6-f0751ed86b5b`. A saída capturada dos três termina em `Reading package lists...`, no fim do `apt-get update`. Não há linha de instalação do `less`. O código 141 é o código de SIGPIPE. Os três scripts usam `set -o pipefail` e, em seguida, leem o candidato do apt com `awk` encerrando no primeiro resultado. A versão observada depois da execução continua abaixo de `590-2ubuntu2.1`, então a classificação é FALHA.

## Recursos removidos

A pilha do `wget` foi destruída antes deste experimento: VPC `vpc-07ed5b7db90bfd3a6`, NAT `nat-07030ea6ff070f9d0`, AMI `ami-03629c5c47c71759b` e snapshot `snap-00f4c9aff7066895b`. A pilha do `less` foi destruída às 14:09, depois da coleta: VPC `vpc-020c46e60ddbaf0df`, NAT `nat-0efd3e841d92248d6`, AMI `ami-0c49cb4a0e4553411` e snapshot `snap-06132306270db8c11`. A instância parada CopySpider não faz parte deste laboratório e não foi alterada.

## Leitura para o TCC

Neste conjunto, o modelo produziu três scripts sintaticamente aceitos pelo validador, e nenhum deles concluiu a atualização do pacote. Isso não altera as taxas do `wget` e não mede redução de esforço manual.
