#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <list>
#include <optional>
#include <cstdint>
#include <algorithm>
#include <variant>

using namespace std;

// Resource Record
struct RR
{
  string name; 
  uint16_t type = 1;    // A
  uint16_t rrclass = 1; // IN
  uint32_t ttl = 0;
  vector<uint8_t> rdata; // em bytes
};

struct SOAMeta
{
  uint32_t minimum = 0; // para TTL negativo (RFC 2308)
};

struct CacheKey
{
  string qname; // normalizado (lowercase, sem trailing dot)
  uint16_t qtype = 1;
  uint16_t qclass = 1; // IN

  inline bool operator == (const CacheKey& o) const
  {
    return qtype == o.qtype && qclass == o.qclass && qname == o.qname;
  }
};

// Combina hash do nome com qtype num inteiro
struct CacheKeyHash
{
  size_t operator()(const CacheKey& k) const
  {
    hash<string> h1;
    hash<uint64_t> h2;

    return h1(k.qname) ^ (h2((uint64_t)k.qtype << 32 | k.qclass));
  }
};

// Entrada positiva da cache
struct PositiveEntry
{
  vector<RR> rrset;
  uint64_t expires_at_ms = 0; // Horário de expiração
  uint8_t rcode = 0; // NOERROR
};

// NXDOMAIN (dado não existe) NODATA(nome existe, mas não esse tipo)
enum class NegKind { NXDOMAIN, NODATA };

struct NegativeEntry
{
  NegKind kind = NegKind::NODATA;
  uint64_t expires_at_ms = 0;
  uint8_t rcode = 0; // 3 para NXDOMAIN; 0 para NODATA
  optional<SOAMeta> soa;
};

// Estrutura principal da cache
class DnsCache
{
public:
  // Construtor define a capacidade, escolhi 50/50 (pos/neg)
  explicit DnsCache(size_t cap_pos = 50, size_t cap_neg = 50);

  // Leitura da cache
  optional<PositiveEntry> getPositive(const CacheKey& key, uint64_t now_ms);
  optional<NegativeEntry> getNegative(const CacheKey& key, uint64_t now_ms);

  // Escrita na cache
  void putPositive(const CacheKey& key, PositiveEntry entry, uint64_t now_ms);
  void putNegative(const CacheKey& key, NegativeEntry entry, uint64_t now_ms);

  // Remoção de entradas expiradas
  void purgeExpired(uint64_t now_ms);

private:
  // LRU: lista de chaves; frente = mais recente
  using EntryVariant = variant<PositiveEntry, NegativeEntry>;

  struct Node
  {
      EntryVariant val;
      uint64_t expires_at_ms = 0;
      list<CacheKey>::iterator it_lru; // posição na LRU
  };

  // Estrutura única:
  unordered_map<CacheKey, Node, CacheKeyHash> map_;
  list<CacheKey> lru_; // frente = mais recente

  // Cotas
  size_t cap_pos_;
  size_t cap_neg_;
  size_t pos_count_ = 0;
  size_t neg_count_ = 0;

  // Helpers internos
  void touch_(list<CacheKey>::iterator it);
  bool isExpired_(uint64_t now_ms, const Node& n) const;

  // Remoção (ajusta contadores)
  void eraseNode_(const CacheKey& key, const Node& n);

  // Evicção por cotas: remove do fim da LRU,
  // mas apenas o tipo que estiver acima da sua cota.
  void evictIfNeeded_();
};
