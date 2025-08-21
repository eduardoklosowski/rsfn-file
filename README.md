# Utilitário para Arquivos que Trafegam na RSFN (Rede do Sistema Financeiro Nacional)

## Exemplos de Uso

### Mostrar e Validar o Cabeçalho de Segurança de um Arquivo

```txt
$ rsfnfile header -i arquivo-criptografado
================================ BEGIN HEADER ================================
C01 Tamanho do cabeçalho                     : 0x024c [588]
C02 Versão do protocolo                      : 0x03 [Terceira versão]
C03 Código de erro                           : 0x00 [Sem erros]
C04 Tratamento especial                      : 0x00 [Uso normal]
C05 Reservado                                : 0x00 [-]
C06 Algoritmo da chave assimétrica do destino: 0x02 [RSA com 2048 bits]
C07 Algoritmo da chave simétrica             : 0x02 [AES com 256 bits]
C08 Algoritmo da chave assimétrica local     : 0x02 [RSA com 2048 bits]
C09 Algoritmo de hash                        : 0x03 [SHA-256]
C10 PC do certificado do destino             : 0x01 [SPB-Serpro]
C11 Série do certificado do destino          : 0x00000000000000000000000000000000000000000000000000000a0b0c0d0e0f [0a:0b:0c:0d:0e:0f]
C12 PC do certificado da instituição         : 0x03 [Pessoas Físicas]
C13 Série do certificado da instituição      : 0x0000000000000000000000000000000000000000000000000000fafbfcfdfeff [fa:fb:fc:fd:fe:ff]
C14 Buffer da chave simétrica                : blob [len=256]
C15 Buffer da autenticação da mensagem       : blob [len=256]
================================ END HEADER ================================
```
