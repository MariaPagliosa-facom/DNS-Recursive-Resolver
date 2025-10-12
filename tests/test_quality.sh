#!/bin/bash

echo "=== Teste de Qualidade e Funcionalidades Avançadas ==="

# Teste 1: Diferentes tipos de consulta
echo "1. Consulta CNAME:"
../tp1dns_cli --ns 198.41.0.4 --name www.github.com --qtype CNAME --iter

echo -e "\n2. Consulta TXT:"
../tp1dns_cli --ns 198.41.0.4 --name google.com --qtype TXT --iter

echo -e "\n3. Consulta SOA:"
../tp1dns_cli --ns 198.41.0.4 --name google.com --qtype SOA --iter

# Teste 2: EDNS
echo -e "\n4. Consulta com EDNS:"
../tp1dns_cli --ns 198.41.0.4 --name example.com --qtype A --iter

# Teste 3: Domínios internacionais
echo -e "\n5. Domínio com acentuação (IDN):"
../tp1dns_cli --ns 198.41.0.4 --name café.com --qtype A --iter