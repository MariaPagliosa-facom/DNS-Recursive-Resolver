#!/bin/bash

echo "=== EXECUTANDO TODOS OS TESTES ==="
echo "Data: $(date)"
echo "Diretório: $(pwd)"
echo

# Verificar se os executáveis foram construídos
if [ ! -f "../tp1dns_cli" ]; then
    echo "ERRO: tp1dns_cli não encontrado"
    echo "Execute 'cmake --build build' primeiro"
    exit 1
fi

# Executar testes em sequência
echo ">>> Teste 1: Resolução Recursiva e Iterativa"
./test_recursive_iterative.sh
echo

echo ">>> Teste 2: DNS-over-TLS"
./test_dot.sh
echo

echo ">>> Teste 3: Sistema de Cache"
./test_cache.sh
echo

echo ">>> Teste 4: Qualidade e Funcionalidades"
./test_quality.sh
echo

echo ">>> Teste 5: Integração Completa"
./test_integration.sh
echo

echo ">>> Teste 6: Tratamento de Erros"
./test_errors.sh
echo

echo "=== TODOS OS TESTES CONCLUÍDOS ==="

# Limpeza
pkill -f cache_daemon 2>/dev/null