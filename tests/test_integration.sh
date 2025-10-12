#!/bin/bash

echo "=== Teste de Integração Completa ==="

# Configurar ambiente
if ! pgrep -f "cache_daemon" > /dev/null; then
    echo "Iniciando serviços..."
    ../cache_daemon &
    sleep 2
fi

# Teste integrado: DoT + Cache + Resolução Iterativa
echo "1. Resolução completa com todos os componentes:"
../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com --iter --trace

echo -e "\n2. Verificar cache após resolução:"
../cachectl get example.com A

echo -e "\n3. Segunda consulta (deve usar cache):"
../tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com --iter

# Teste de performance
echo -e "\n4. Teste de performance com cache:"
echo "Primeira execução:"
time ../tp1dns_cli --ns 198.41.0.4 --name example.com --qtype A --iter > /dev/null 2>&1
echo -e "\nSegunda execução (com cache):"
time ../tp1dns_cli --ns 198.41.0.4 --name example.com --qtype A --iter > /dev/null 2>&1