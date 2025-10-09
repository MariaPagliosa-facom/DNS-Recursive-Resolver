#pragma once
#include <string>
#include <vector>
#include <cstdint>

using namespace std;

// Envia DNS/UDP (porta 53)
// timeout_ms aplica em send e recv.
vector<uint8_t> sendUDP(const string& server_ip, uint16_t port,
                        const vector<uint8_t>& payload, int timeout_ms);

// Envia DNS/TCP (porta 53) com prefixo de 2 bytes (tamanho)
// timeout_ms aplica em connect, send e recv.
// Retorna APENAS o payload DNS (sem os 2 bytes do tamanho).
vector<uint8_t> sendTCP(const string& server_ip, uint16_t port,
                        const vector<uint8_t>& payload, int timeout_ms);
