#!/bin/bash

echo "=== Teste de Sistema de Cache ==="

# Iniciar o daemon de cache se não estiver rodando
if ! pgrep -f "cache_daemon" > /dev/null; then
    echo "Iniciando cache_daemon..."
    ../cache_daemon &
    sleep 2
fi

# Teste 1: Consultas repetidas para verificar cache
echo "1. Primeira consulta (cache miss):"
../tp1dns_cli --ns 198.41.0.4 --name example.com --qtype A --iter

echo -e "\n2. Segunda consulta (deve usar cache):"
../tp1dns_cli --ns 198.41.0.4 --name example.com --qtype A --iter

# Teste 2: Cache de respostas negativas
echo -e "\n3. Consulta para domínio inexistente (NXDOMAIN):"
../tp1dns_cli --ns 198.41.0.4 --name "dominio-inexistente-$(date +%s).com" --qtype A --iter

echo -e "\n4. Reconsulta para domínio inexistente (deve usar cache negativo):"
../tp1dns_cli --ns 198.41.0.4 --name "dominio-inexistente-$(date +%s).com" --qtype A --iter

# Teste 3: Ferramenta de controle de cache
echo -e "\n5. Status do cache via cachectl:"
../cachectl status

echo -e "\n6. Consulta direta no cache:"
../cachectl get example.com A