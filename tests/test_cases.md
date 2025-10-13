# Casos de Teste

## Validação Funcional Básica
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

## Testes de Protocolo
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

## Avaliação do Sistema de Cache
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

## Testes de Integração
- [CT10]
    ```bash
    ../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com --iter --trace
    ../cachectl get example.com A
    ../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com --iter
- [CT11]
    ```bash
    time ../tp1dns_cli --ns 198.41.0.4 --name example.com --qtype A --iter > /dev/null 2>&1
    time ../tp1dns_cli --ns 198.41.0.4 --name example.com --qtype A --iter > /dev/null 2>&1