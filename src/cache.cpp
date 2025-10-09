#include "cache.h"

bool
DnsCache::isExpired_(uint64_t now_ms, const Node& n) const
{
  return now_ms >= n.expires_at_ms;
}

// Construtor salva a capacidade max de positivos e negativos
DnsCache::DnsCache(size_t cap_pos, size_t cap_neg)
  : cap_pos_(cap_pos), cap_neg_(cap_neg) {}

// Reordena o item acessado para o início da fina
void
DnsCache::touch_(list<CacheKey>::iterator it)
{
  // move para frente (mais recente)
  lru_.splice(lru_.begin(), lru_, it);
}

void
DnsCache::eraseNode_(const CacheKey& key, const Node& n)
{
  // Ajusta contadores conforme o tipo
  if (holds_alternative<PositiveEntry>(n.val))
  {
    if (pos_count_ > 0)
        --pos_count_;
  }
  else
  {
    if (neg_count_ > 0)
        --neg_count_;
  }
  lru_.erase(n.it_lru);
  map_.erase(key);
}

// Se o map exceder a capacidade, remove os menos recentes
void
DnsCache::evictIfNeeded_()
{
  // Enquanto uma das cotas estiver estourada, remove do fundo
  while ((pos_count_ > cap_pos_) || (neg_count_ > cap_neg_))
  {
    if (lru_.empty())
      break;

    // Procura do fundo (menos recente) o 1º do tipo que está acima da cota
    auto it_tail = lru_.end();

    --it_tail;

    // Em alguns casos, o item do fundo pode ser do "tipo certo",
    // senão caminhamos para trás até encontrar um do tipo que precisa ser evicto.
    bool removed = false;

    for (auto it = it_tail; ; )
    {
      const CacheKey& key = *it;
      auto m = map_.find(key);

      if (m != map_.end())
      {
        bool isPos = holds_alternative<PositiveEntry>(m->second.val);

        if ((isPos && pos_count_ > cap_pos_) || (!isPos && neg_count_ > cap_neg_))
        {
          eraseNode_(key, m->second);
          removed = true;
          break;
        }
      }
      if (it == lru_.begin())
        break;
      --it;
    }

    // Se não achou nada para remover (pouco provável), quebra pra evitar loop
    if (!removed) break;
  }
}

// Busca positiva
optional<PositiveEntry>
DnsCache::getPositive(const CacheKey& key, uint64_t now_ms)
{
  auto it = map_.find(key);

  if (it == map_.end())
    return nullopt;

  Node& n = it->second;

  if (isExpired_(now_ms, n))
  {
    eraseNode_(key, n);
    return nullopt;
  }
  if (!holds_alternative<PositiveEntry>(n.val))
  {
    // Existe entrada, mas é negativa → não é um "hit" positivo
    return nullopt;
  }
  touch_(n.it_lru);
  return get<PositiveEntry>(n.val);
}

// Busca negativa
optional<NegativeEntry>
DnsCache::getNegative(const CacheKey& key, uint64_t now_ms)
{
  auto it = map_.find(key);

  if (it == map_.end())
    return nullopt;

  Node& n = it->second;

  if (isExpired_(now_ms, n))
  {
    eraseNode_(key, n);
    return nullopt;
  }

  if (!holds_alternative<NegativeEntry>(n.val))
  {
    return nullopt;
  }

  touch_(n.it_lru);
  return get<NegativeEntry>(n.val);
}

void
DnsCache::putPositive(const CacheKey& key, PositiveEntry entry, uint64_t /*now_ms*/)
{
  auto it = map_.find(key);

  if (it != map_.end())
  {
    // Atualiza, mantendo a posição na LRU
    Node& n = it->second;

    // Se era negativa, ajusta contadores
    if (holds_alternative<NegativeEntry>(n.val))
    {
      if (neg_count_ > 0)
        --neg_count_;
      ++pos_count_;
    }
    n.expires_at_ms = entry.expires_at_ms;
    n.val = move(entry);
    touch_(n.it_lru);
  }
  else
  {
    // Novo
    lru_.push_front(key);

    Node n;

    n.it_lru = lru_.begin();
    n.expires_at_ms = entry.expires_at_ms;
    n.val = move(entry);
    map_.insert({key, move(n)});
    ++pos_count_;
  }

  evictIfNeeded_();
}

void
DnsCache::putNegative(const CacheKey& key, NegativeEntry entry, uint64_t /*now_ms*/)
{
  auto it = map_.find(key);

  if (it != map_.end())
  {
    Node& n = it->second;
    
    if (holds_alternative<PositiveEntry>(n.val))
    {
      if (pos_count_ > 0)
        --pos_count_;
      ++neg_count_;
    }
    n.expires_at_ms = entry.expires_at_ms;
    n.val = move(entry);
    touch_(n.it_lru);
  }
  else
  {
    lru_.push_front(key);

    Node n;

    n.it_lru = lru_.begin();
    n.expires_at_ms = entry.expires_at_ms;
    n.val = move(entry);
    map_.insert({key, move(n)});
    ++neg_count_;
  }

  evictIfNeeded_();
}

void
DnsCache::purgeExpired(uint64_t now_ms)
{
  for (auto it = map_.begin(); it != map_.end(); )
  {
    Node& n = it->second;

    if (isExpired_(now_ms, n))
    {
      // Apaga com ajuste de contadores
      auto to_erase = it++;

      eraseNode_(to_erase->first, to_erase->second);
    }
    else
    {
      ++it;
    }
  }
}