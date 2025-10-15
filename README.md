# Resolvedor Recursivo DNS (com Cache e DoT)

Implementação de um **resolvedor recursivo DNS** do zero, usando **sockets básicos** (UDP/TCP) e **DNS over TLS (DoT)** no modo de 1 salto, com **cache positiva e negativa** local e via **daemon**.

## Funcionalidades
- Resolução **iterativa** (RD=0) com **delegações** (NS + glue).
- Suporte a **CNAME** encadeado.
- **Respostas negativas**: **NXDOMAIN** e **NODATA** com TTL negativo (SOA).
- **Fallback TCP** quando **TC=1** (truncamento no UDP).
- **Cache**:
  - **Positiva**: RRset + TTL mínimo;
  - **Negativa**: NXDOMAIN/NODATA + TTL (SOA.minimum);
  - **Local por processo** e via **daemon** externo (socket de texto).
- **DoT (DNS over TLS)** no **modo 1 salto** (recursivos públicos: 1.1.1.1, 8.8.8.8).
    > DoT é aplicado somente no modo 1 salto (recursivos). No modo iterativo, usamos UDP/TCP, pois autoritativos raramente oferecem DoT.
- Logs de **trace** com `--trace`.

> Não utilizamos bibliotecas “DNS prontas”. O wire format, sockets e a lógica de resolução foram implementados manualmente.

## Requisitos

- **Ubuntu/WSL2** (ou Linux equivalente)
- **CMake** e **g++ (C++17)**
- **OpenSSL** (para DoT)
- Pacotes:
  ```bash
  sudo apt-get update
  sudo apt-get install -y build-essential cmake libssl-dev ca-certificates
  sudo update-ca-certificates

## Compilação

    cmake -S . -B build
    cmake --build build -j

# Casos de Teste

Abra a basta criada pelo compilador para poder realizar os testes abaixo (referenciados no relatório).
```
cd build/tests/
```

É possível executar todos os testes de uma vez só:
```
./run_all_tests.sh
```

Ou escolher qual dos blocos abaixo serão executados:

```
./test_recursive_iterative.sh
./test_dot.sh
./test_cache.sh
./test_integration.sh
```

## Validação Funcional Básica <./test_recursive_iterative.sh>
- [CT01]
    ```bash
    ../tp1dns_cli --ns 198.41.0.4 --name www.google.com --qtype A --iter --trace
    ../tp1dns_cli --ns 198.41.0.4 --name www.github.com --qtype A --iter
- [CT02]
    ```bash
    ../tp1dns_cli --ns 198.41.0.4 --name www.ufms.br --qtype A --iter --trace
- [CT03]
    ```bash
    ../tp1dns_cli --ns 198.41.0.4 --name google.com --qtype NS --iter
    ../tp1dns_cli --ns 198.41.0.4 --name gmail.com --qtype MX --iter
    ../tp1dns_cli --ns 198.41.0.4 --name facebook.com --qtype AAAA --iter

## Testes de Protocolo <./test_dot.sh>
- [CT04]
    ```bash
    ../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com
    ../tp1dns_cli --ns 8.8.8.8 --name example.com --qtype AAAA --mode dot --sni dns.google
- [CT05]
    ```bash
    ../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com --insecure-dot
- [CT06]
    ```bash
    ../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A
    ../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com

## Avaliação do Sistema de Cache <./test_cache.sh>
- [CT07]
    ```bash
    ../tp1dns_cli --ns 198.41.0.4 --name example.com --qtype A --iter
    ../tp1dns_cli --ns 198.41.0.4 --name example.com --qtype A --iter
- [CT08]
    ```bash
    ../tp1dns_cli --ns 198.41.0.4 --name "dominio-inexistente-$(date +%s).com" --qtype A --iter
    ../tp1dns_cli --ns 198.41.0.4 --name "dominio-inexistente-$(date +%s).com" --qtype A --iter
- [CT09]
    ```bash
    ../cachectl status
    ../cachectl get example.com A

## Testes de Integração <./test_integration.sh>
- [CT10]
    ```bash
    ../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com --iter --trace
    ../cachectl get example.com A
    ../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com --iter
- [CT11]
    ```bash
    time ../tp1dns_cli --ns 198.41.0.4 --name example.com --qtype A --iter > /dev/null 2>&1
    time ../tp1dns_cli --ns 198.41.0.4 --name example.com --qtype A --iter > /dev/null 2>&1
