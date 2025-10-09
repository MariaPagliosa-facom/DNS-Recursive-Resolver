#pragma once
#include <cstdint>
#include <string>
#include <vector>

using namespace std;

// Cabeçalho DNS
struct DnsHeader
{
  uint16_t id = 0;
  uint16_t flags = 0;     // QR|Opcode|AA|TC|RD|RA|Z|RCODE
  uint16_t qdcount = 0;   // Contadores de seções: Questions, Answers,
  uint16_t ancount = 0;   // Authority (NS), Aditional (AR)
  uint16_t nscount = 0;
  uint16_t arcount = 0;
};

// Questão da query
struct DnsQuestion
{
  string qname;      // nome “humano”
  uint16_t qtype = 1;     // A=1, AAAA=28, ...
  uint16_t qclass = 1;    // IN=1
};

// RR genérico (para parse e posterior mapeamento p/ cache)
struct DnsRR
{
  string name;
  uint16_t type = 1;
  uint16_t rrclass = 1; // IN=1
  uint32_t ttl = 0;
  vector<uint8_t> rdata; // bytes crus
  uint32_t rdata_offset = 0;  // offset do RDATA na mensagem original
};

// Mensagem DNS, separando cada seção
struct DnsMessage
{
  DnsHeader header;
  vector<DnsQuestion> questions;
  vector<DnsRR> answers;
  vector<DnsRR> authorities;
  vector<DnsRR> additionals;
  vector<uint8_t> wire; // c;opia da mensagem bruta
};

// Monta uma query DNS (Header + Question [+ OPT/EDNS])
// use_edns = true adiciona RR OPT (type=41) para payload UDP maior.
vector<uint8_t> buildQuery(const string& qname,
                                uint16_t qtype,
                                bool use_edns);

// Faz o parse de uma mensagem DNS completa (Header, Q, RR).
// Retorna false se houver erro óbvio (buffer curto, etc).
bool parseMessage(const vector<uint8_t>& data, DnsMessage& out);

// Normaliza nome: lower-case e sem ponto final.
string toLowerName(const string& name);

// Constantes úteis
namespace dnstype
{
  constexpr uint16_t A = 1;
  constexpr uint16_t NS = 2;
  constexpr uint16_t CNAME = 5;
  constexpr uint16_t SOA = 6;
  constexpr uint16_t MX = 15;
  constexpr uint16_t TXT = 16;
  constexpr uint16_t AAAA = 28;
}

// Converte RDATA de A/AAAA para string ("1.2.3.4" ou "::1"). Retorna "" se tipo não bater.
string rdataToIPString(const DnsRR& rr);

// Decodifica um NAME (com compressão) a partir do início do RDATA (para NS/CNAME).
// Retorna "" se tipo não bater ou se falhar.
string rdataToDomainName(const DnsRR& rr, const DnsMessage& msg);

// Extrai SOA.MINIMUM (TTL negativo sugerido pela RFC 2308). Retorna {ok, minimum}.
pair<bool, uint32_t> rdataSOAMinimum(const DnsRR& rr, const DnsMessage& msg);