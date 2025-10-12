#!/bin/bash

echo "=== Teste de DNS-over-TLS (DoT) ==="

# Teste 1: DoT com Cloudflare
echo "1. DoT com Cloudflare DNS:"
../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com

echo -e "\n2. DoT com Google DNS:"
../tp1dns_cli --ns 8.8.8.8 --name example.com --qtype AAAA --mode dot --sni dns.google

# Teste 2: DoT com modo inseguro (para testes)
echo -e "\n3. DoT com validação de certificado desativada:"
../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com --insecure-dot

# Teste 3: Comparação DNS vs DoT
echo -e "\n4. Comparação DNS tradicional vs DoT:"
echo "DNS tradicional:"
../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A
echo -e "\nDoT:"
../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com