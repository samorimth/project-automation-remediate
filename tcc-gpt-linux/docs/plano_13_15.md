# Plano de 13, 14 e 15 de novembro de 2026

Atualização da noite de 12 de novembro: a CVE-2024-32487 já foi executada. Três scripts foram gerados e os três falharam no SSM com código 141. As pilhas do `wget` e do `less` foram destruídas. O texto abaixo era o plano anterior a essa execução. O uso imediato desses dias é incorporar o resultado em `docs/resultado_cve_2024_32487.md` no material da pré-banca, sem tratar a falha como sucesso.

A pré-banca é em 16 de novembro. Nada desta lista cria recurso nem chama a API sem uma frase nova de autorização.

## 13 de novembro

- Decidir se a CVE-2024-32487 (`less`) é a segunda CVE.
- Se for aprovada, conferir de novo o tracker e o OSV antes de gravar a AMI.
- Preparar o texto da pré-banca com `docs/levantamento_inicial_tcc.md`, separando o conjunto histórico do conjunto da reexecução.
- Manter a VPC e o NAT desligados se a frase `AUTORIZO_DESTRUIR_RECURSOS` for dada antes desse dia. Enquanto o NAT `nat-07030ea6ff070f9d0` estiver ligado, o custo horário continua.

## 14 de novembro

- Com `AUTORIZO_RECURSOS_PAGOS`, criar a AMI privada do `less` e destruir a instância auxiliar.
- Com autorização de API e saldo, gerar três scripts novos, com o mesmo modelo, o mesmo prompt e os mesmos parâmetros. Não reaproveitar os scripts do `wget`.
- Validar os três arquivos. Script reprovado não vai para o SSM.

## 15 de novembro

- Com `AUTORIZO_EXECUCAO_SCRIPT_IA`, executar cada script aprovado em uma EC2 nova da AMI do `less`, uma instância por vez.
- Conferir a versão antes e depois, mais um teste funcional do `less` que não explore a CVE.
- Destruir cada EC2 depois da coleta.
- Reunir os dois conjuntos no texto final, sem somar as taxas do `wget` às do `less`.
- Destruir a infraestrutura compartilhada e as AMIs privadas somente com `AUTORIZO_DESTRUIR_RECURSOS`.

Se a segunda CVE não for aprovada até o dia 14, o material da pré-banca fica limitado ao `wget`, com essa limitação escrita de forma explícita.
