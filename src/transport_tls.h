#pragma once
#include <string>
#include <vector>
#include <cstdint>

// Envia DNS sobre TLS (DoT) para ns_ip:port usando SNI.
// Retorna o payload DNS (sem os 2 bytes de length do TCP), ou vazio em erro.
// Se insecure=true, NÃO valida o certificado (apenas para diagnóstico).
std::vector<uint8_t> sendDoT(const std::string& ns_ip,
                             uint16_t port,
                             const std::vector<uint8_t>& query,
                             const std::string& sni,
                             int timeout_ms,
                             bool insecure);
