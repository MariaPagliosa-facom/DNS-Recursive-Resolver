#!/bin/bash

echo "=== Teste de Resolução Recursiva e Iterativa ==="

# Teste 1: Resolução recursiva começando de root server
echo "1. Resolução recursiva de www.google.com a partir de root server:"
../tp1dns_cli --ns 198.41.0.4 --name www.google.com --qtype A --iter --trace

echo -e "\n2. Resolução recursiva de www.github.com a partir de root server:"
../tp1dns_cli --ns 198.41.0.4 --name www.github.com --qtype A --iter

# Teste 2: Resolução iterativa com trace
echo -e "\n3. Resolução iterativa com trace ativado:"
../tp1dns_cli --ns 198.41.0.4 --name www.ufms.br --qtype A --iter --trace

# Teste 3: Diferentes tipos de registro
echo -e "\n4. Consulta de registro NS:"
../tp1dns_cli --ns 198.41.0.4 --name google.com --qtype NS --iter

echo -e "\n5. Consulta de registro MX:"
../tp1dns_cli --ns 198.41.0.4 --name gmail.com --qtype MX --iter

echo -e "\n6. Consulta de registro AAAA (IPv6):"
../tp1dns_cli --ns 198.41.0.4 --name facebook.com --qtype AAAA --iter