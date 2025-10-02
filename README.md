# RSFN File

Esse projeto é uma ferramenta para validar e inspecionar arquivos trafegados na RSFN (Rede do Sistema Financeiro Nacional). Por também possibilitar a criptografia e descriptografia de arquivos, ele se torna uma opção para gerar arquivos visando testar sistemas que interagem na RSFN e validar o conteúdo dos arquivos gerados por esses sistemas.

Atualmente essa ferramenta implementa suporte apenas a versão 3 do cabeçalho de segurança (última versão publicada até então) com os algoritmos de criptografia [AES](https://pt.wikipedia.org/wiki/Advanced_Encryption_Standard), [RSA](https://pt.wikipedia.org/wiki/RSA_(sistema_criptogr%C3%A1fico)) e de hash [SHA-256](https://pt.wikipedia.org/wiki/SHA-2). Sua implementação é baseada nas documentações disponibilizadas pelo [Banco Cental do Brasil](https://www.bcb.gov.br/estabilidadefinanceira/comunicacaodados) e [Núclea](https://www2.nuclea.com.br/SitePages/novodocumentos.aspx) para serviços como STR e SLC.

## Exemplos de Uso

[![Vídeo no asciicast](https://asciinema.org/a/746604.svg)](https://asciinema.org/a/746604)

### Mostrar e Validar o Cabeçalho de Segurança de um Arquivo

```txt
$ rsfnfile header arquivo-criptografado
================================ BEGIN HEADER ================================
C01 Tamanho do cabeçalho                     : 0x024c [588]
C02 Versão do protocolo                      : 0x03 [Terceira versão]
C03 Código de erro                           : 0x00 [Sem erros]
C04 Tratamento especial                      : 0x08 [Arquivo compactado]
C05 Reservado                                : 0x00 [-]
C06 Algoritmo da chave assimétrica do destino: 0x02 [RSA com 2048 bits]
C07 Algoritmo da chave simétrica             : 0x02 [AES com 256 bits]
C08 Algoritmo da chave assimétrica local     : 0x02 [RSA com 2048 bits]
C09 Algoritmo de hash                        : 0x03 [SHA-256]
C10 PC do certificado do destino             : 0x01 [SPB-Serpro]
C11 Série do certificado do destino          : 0x3030303030303030303030303030303030303030303030303030313233343536 [0x123456]
C12 PC do certificado da instituição         : 0x01 [SPB-Serpro]
C13 Série do certificado da instituição      : 0x3030303030303030303030303030303030303030303030303030414243444546 [0xabcdef]
C14 Buffer da chave simétrica                : blob [len=256]
C15 Buffer da autenticação da mensagem       : blob [len=256]
================================ END HEADER ================================
```

### Criptografa Arquivo

```txt
$ make certs
$ echo "Exemplo de teste" | rsfnfile enc data/part-a.crt data/part-a.key data/part-b.crt --gzip -o arquivo-criptografado
```

### Descriptografa Arquivo

```txt
$ rsfnfile dec data/part-a.crt data/part-b.crt data/part-b.key arquivo-criptografado
Exemplo de teste
```
