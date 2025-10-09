#include "resolver.h"
#include "dns_wire.h"
#include "transport.h"
#include <chrono>
#include <cctype>
#include <algorithm>
#include <unordered_map>
#include <cstdio>
#include <cstdarg>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>   // inet_ntop, AF_INET6, INET6_ADDRSTRLEN
#endif

// Utilidades simples
static uint16_t
toType(const string& s)
{
  string u;

  u.reserve(s.size());
  for (char c : s)
    u.push_back(static_cast<char>(toupper((unsigned char)c)));
  if (u == "A")
    return 1;
  if (u == "NS")
    return 2;
  if (u == "CNAME")
   return 5;
  if (u == "SOA")
   return 6;
  if (u == "MX")
   return 15;
  if (u == "TXT")
   return 16;
  if (u == "AAAA")
   return 28;
  return 1; // default A
}

static string
norm(const string& s)
{
  return toLowerName(s);
}

uint64_t
Resolver::nowMs() const
{
  using namespace chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

uint16_t
Resolver::parseType(const string& qtype)
{
  return toType(qtype);
}

// --- helper trace ---
void
Resolver::TRACE(const char* fmt, ...) const
{
  if (!trace_)
    return;

  va_list ap;
  va_start(ap, fmt);

  fprintf(stderr, "[trace] ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}

// Consulta de 1 salto (suporta DoT)
optional<SingleQueryResult>
Resolver::singleQueryTo(const string& ns_ip,
                        const string& qname_in,
                        const string& qtype_in,
                        bool use_edns,
                        int timeout_ms)
{
  SingleQueryResult out;
  const string qname = toLowerName(qname_in);
  const uint16_t qtype = parseType(qtype_in);
  auto q = buildQueryBytes(qname, qtype, use_edns);
  DnsMessage msg;
  bool via_tcp = false;

  if (mode_ == Mode::DOT)
  {
    auto resp = sendDoT(ns_ip, 853, q, sni_, timeout_ms, dot_insecure_);

    if (resp.empty())
      return nullopt;
    if (!parseMessage(resp, msg))
      return nullopt;
    via_tcp = true; // DoT corre sobre TCP
  }
  else
  {
    // caminho: UDP e, se TC=1, fallback para TCP
    auto resp = sendUDP(ns_ip, 53, q, timeout_ms);

    if (resp.empty())
      return nullopt;
    if (!parseMessage(resp, msg))
      return nullopt;
    if (hasTC(msg))
    {
      via_tcp = true;

      auto resp2 = sendTCP(ns_ip, 53, q, timeout_ms);

      if (resp2.empty())
        return nullopt;
      if (!parseMessage(resp2, msg))
        return nullopt;
    }
  }

  out.ok = true;
  out.via_tcp = via_tcp;
  out.rcode = getRCODE(msg);
  out.message = move(msg);
  return out;
}

// Helpers de envio e análise de mensagem
vector<uint8_t>
Resolver::buildQueryBytes(const string& qname, uint16_t qtype, bool use_edns) const
{
  return buildQuery(qname, qtype, use_edns);
}

bool
Resolver::sendOnce(const string& ns_ip,
                   const vector<uint8_t>& q,
                   int timeout_ms,
                   DnsMessage& out,
                   bool& via_tcp)
{
  via_tcp = false;

  auto resp = sendUDP(ns_ip, 53, q, timeout_ms);

  if (resp.empty())
    return false;
  if (!parseMessage(resp, out))
    return false;
  if (hasTC(out))
  {
    via_tcp = true;

    auto resp_tcp = sendTCP(ns_ip, 53, q, timeout_ms);

    if (resp_tcp.empty())
      return false;
    if (!parseMessage(resp_tcp, out))
      return false;
  }
  return true;
}

uint16_t
Resolver::getRCODE(const DnsMessage& m)
{
  return static_cast<uint16_t>(m.header.flags & 0x000F);
}

bool
Resolver::hasTC(const DnsMessage& m)
{
  return (m.header.flags & 0x0200) != 0;
}

bool
Resolver::hasAnswerTypeForName(const DnsMessage& m, const string& qname, uint16_t qtype)
{
  const string qn = norm(qname);

  for (const auto& rr : m.answers)
  {
    if (norm(rr.name) == qn && rr.type == qtype && rr.rrclass == 1)
      return true;
  }
  return false;
}
vector<DnsRR>
Resolver::collectAnswerTypeForName(const DnsMessage& m, const string& qname, uint16_t qtype)
{
  vector<DnsRR> v;
  const string qn = norm(qname);

  for (const auto& rr : m.answers)
  {
    if (norm(rr.name) == qn && rr.type == qtype && rr.rrclass == 1)
      v.push_back(rr);
  }
  return v;
}
optional<string>
Resolver::findCNAMEtargetFor(const DnsMessage& m, const string& qname)
{
  const string qn = norm(qname);

  for (const auto& rr : m.answers)
  {
    if (rr.type == dnstype::CNAME && rr.rrclass == 1 && norm(rr.name) == qn)
    {
      auto tgt = rdataToDomainName(rr, m);

      if (!tgt.empty())
        return norm(tgt);
    }
  }
  return nullopt;
}
vector<string>
Resolver::collectNSNames(const DnsMessage& m)
{
  vector<string> out;

  for (const auto& rr : m.authorities)
  {
    if (rr.type == dnstype::NS && rr.rrclass == 1)
    {
      auto nsn = rdataToDomainName(rr, m);

      if (!nsn.empty())
        out.push_back(norm(nsn));
    }
  }
  return out;
}
vector<string>
Resolver::collectGlueIPsFor(const DnsMessage& m, const unordered_set<string>& ns_names)
{
  vector<string> ips;

  for (const auto& rr : m.additionals) 
  {
    if ((rr.type == dnstype::A || rr.type == dnstype::AAAA) && rr.rrclass == 1)
    {
      if (ns_names.count(norm(rr.name)))
      {
        auto ip = rdataToIPString(rr);

        if (!ip.empty())
          ips.push_back(ip);
      }
    }
  }
  return ips;
}
optional<uint32_t>
Resolver::negativeTTL_from_SOA(const DnsMessage& m)
{
  for (const auto& rr : m.authorities)
  {
    if (rr.type == dnstype::SOA && rr.rrclass == 1)
    {
      auto p = rdataSOAMinimum(rr, m);

      if (p.first)
        return p.second;
      return rr.ttl; // fallback conservador
    }
  }
  return nullopt;
}

// Cache helpers
vector<RR>
Resolver::toRRsetForCache(const vector<DnsRR>& v)
{
  vector<RR> r;

  r.reserve(v.size());
  for (const auto& x : v)
  {
    RR y;

    y.name = norm(x.name);
    y.type = x.type;
    y.rrclass = x.rrclass;
    y.ttl = x.ttl;
    y.rdata = x.rdata;
    r.push_back(move(y));
  }
  return r;
}

uint32_t
Resolver::minTTL(const vector<DnsRR>& v)
{
  uint32_t m = 0xFFFFFFFFu;

  for (const auto& rr : v)
    m = min<uint32_t>(m, rr.ttl);
  if (m == 0xFFFFFFFFu)
    m = 0;
  return m;
}
void
Resolver::putPositiveCache(const string& qname_norm, uint16_t qtype, const vector<DnsRR>& rrset)
{
  PositiveEntry pe;

  pe.rrset = toRRsetForCache(rrset);

  uint32_t ttl_min = minTTL(rrset);
  uint64_t now = nowMs();

  pe.expires_at_ms = now + static_cast<uint64_t>(ttl_min) * 1000ull;
  pe.rcode = 0;

  CacheKey key{qname_norm, qtype, 1};

  cache_.putPositive(key, move(pe), now);
}

void
Resolver::putNegativeCache(const string& qname_norm, uint16_t qtype,
                           bool is_nxdomain, optional<uint32_t> neg_ttl_opt)
{
  NegativeEntry ne;

  ne.kind = is_nxdomain ? NegKind::NXDOMAIN : NegKind::NODATA;
  ne.rcode = is_nxdomain ? 3 : 0;

  uint32_t ttl = neg_ttl_opt.value_or(60u);
  uint64_t now = nowMs();

  ne.expires_at_ms = now + static_cast<uint64_t>(ttl) * 1000ull;

  CacheKey key{qname_norm, qtype, 1};

  cache_.putNegative(key, move(ne), now);
}

// Resolver auxiliar para IPs de NS (A/AAAA)
vector<string>
Resolver::resolveHostIPs(const string& start_ns_ip,
                         const string& host,
                         bool use_edns,
                         int timeout_ms,
                         int /*depth_budget*/)
{
  vector<string> ips;
  auto rA = resolveRecursive(start_ns_ip, host, "A", use_edns, timeout_ms);

  if (rA && rA->kind == ResolveResult::Kind::OK)
  {
    for (const auto& rr : rA->rrset)
    {
      if (rr.type == dnstype::A && rr.rrclass == 1 && rr.rdata.size() == 4)
      {
        ips.push_back(to_string(rr.rdata[0]) + "." + to_string(rr.rdata[1]) + "." +
                      to_string(rr.rdata[2]) + "." + to_string(rr.rdata[3]));
      }
    }
  }

  auto rAAAA = resolveRecursive(start_ns_ip, host, "AAAA", use_edns, timeout_ms);

  if (rAAAA && rAAAA->kind == ResolveResult::Kind::OK)
  {
#ifdef _WIN32
    for (const auto& rr : rAAAA->rrset)
    {
      if (rr.type == dnstype::AAAA && rr.rrclass == 1 && rr.rdata.size() == 16)
      {
        const uint8_t* p = rr.rdata.data();
        char chunk[5];
        string out;

        for (int i = 0; i < 16; i += 2)
        {
          snprintf(chunk, sizeof(chunk), "%02x%02x", p[i], p[i+1]);
          out += chunk;
          if (i < 14)
            out += ":";
        }
        ips.push_back(out);
      }
    }
#else
    for (const auto& rr : rAAAA->rrset)
    {
      if (rr.type == dnstype::AAAA && rr.rrclass == 1 && rr.rdata.size() == 16)
      {
        char buf[INET6_ADDRSTRLEN]{};

        if (::inet_ntop(AF_INET6, rr.rdata.data(), buf, sizeof(buf)))
          ips.push_back(buf);
      }
    }
#endif
  }
  return ips;
}

// Decisão única sobre a resposta (deixa o laço limpo)
Resolver::Decision
Resolver::analyzeResponse(const DnsMessage& m,
                          const string& qname_norm,
                          uint16_t qtype,
                          const string& /*start_ns_ip*/,
                          bool /*use_edns*/,
                          int /*timeout_ms*/)
{
  Decision d;

  d.rcode = getRCODE(m);

  // NXDOMAIN
  if (d.rcode == 3)
  {
    d.kind = Decision::Kind::FINAL_NXDOMAIN;
    d.negative_ttl = negativeTTL_from_SOA(m);
    return d;
  }

  // Erros transitórios: RETRY
  if (d.rcode != 0)
  {
    d.kind = Decision::Kind::RETRY;
    return d;
  }

  // NOERROR
  if (hasAnswerTypeForName(m, qname_norm, qtype))
  {
    d.kind = Decision::Kind::FINAL_OK;
    d.rrset = collectAnswerTypeForName(m, qname_norm, qtype);
    return d;
  }

  if (auto cname = findCNAMEtargetFor(m, qname_norm))
  {
    d.kind = Decision::Kind::CNAME;
    d.cname_target = *cname;
    return d;
  }

  if (auto neg = negativeTTL_from_SOA(m))
  {
    d.kind = Decision::Kind::FINAL_NODATA;
    d.negative_ttl = neg;
    return d;
  }

  auto ns_names_vec = collectNSNames(m);

  if (!ns_names_vec.empty())
  {
    unordered_set<string> ns_set(ns_names_vec.begin(), ns_names_vec.end());
    auto glue_ips = collectGlueIPsFor(m, ns_set);

    d.kind = Decision::Kind::REFERRAL;
    d.next_ns_ips = move(glue_ips);
    d.next_ns_names = move(ns_names_vec);
    return d;
  }

  d.kind = Decision::Kind::RETRY;
  return d;
}

// Núcleo: resolveRecursive (curto e direto) + daemon
optional<ResolveResult>
Resolver::resolveRecursive(const string& start_ns_ip,
                           const string& qname_in,
                           const string& qtype_in,
                           bool use_edns,
                           int timeout_ms)
{
  ResolveResult res;
  const string qname = norm(qname_in);
  const uint16_t qtype = parseType(qtype_in);

  if (!tried_daemon_)
  {
    tried_daemon_ = daemon_.connectOnce(200);
    TRACE("daemon %s", daemon_.isAvailable()?"ON":"OFF");
  }
  TRACE("resolve %s %u (ns_start=%s)", qname.c_str(), qtype, start_ns_ip.c_str());

  // Tenta daemon
  if (daemon_.isAvailable()) 
  {
    if (auto dg = daemon_.get(qname, qtype))
    {
      if (dg->kind == DaemonGetResult::Kind::POSITIVE)
      {
        TRACE("daemon HIT+ %s %u (ttl=%us rr=%zu)", qname.c_str(), qtype, dg->ttl, dg->rrset.size());
        res.kind = ResolveResult::Kind::OK;
        res.rcode = 0;
        res.ttl = dg->ttl;
        res.rrset = dg->rrset;
        return res;
      }
      else if (dg->kind == DaemonGetResult::Kind::NEGATIVE)
      {
        TRACE("daemon HIT- %s %u (ttl=%us rcode=%u)", qname.c_str(), qtype, dg->ttl, dg->rcode);
        res.kind = (dg->rcode==3)? ResolveResult::Kind::NXDOMAIN : ResolveResult::Kind::NODATA;
        res.rcode = dg->rcode;
        res.ttl = dg->ttl;
        return res;
      }
    }
  }

  // Cache local
  const uint64_t now = nowMs();

  cache_.purgeExpired(now);

  CacheKey key{qname, qtype, 1};

  if (auto pos = cache_.getPositive(key, now))
  {
    TRACE("cache HIT+ %s %u (ttl=%llus)", qname.c_str(), qtype,
          (unsigned long long)((pos->expires_at_ms>now?pos->expires_at_ms-now:0)/1000));
    res.kind = ResolveResult::Kind::OK;
    res.ttl = static_cast<uint32_t>((pos->expires_at_ms > now ? pos->expires_at_ms - now : 0)/1000);
    res.rrset = pos->rrset;
    res.rcode = 0;
    return res;
  }
  if (auto neg = cache_.getNegative(key, now))
  {
    TRACE("cache HIT- %s %u (ttl=%llus kind=%s)", qname.c_str(), qtype,
          (unsigned long long)((neg->expires_at_ms>now?neg->expires_at_ms-now:0)/1000),
          (neg->kind==NegKind::NXDOMAIN?"NXDOMAIN":"NODATA"));
    res.kind = (neg->kind == NegKind::NXDOMAIN) ? ResolveResult::Kind::NXDOMAIN : ResolveResult::Kind::NODATA;
    res.ttl = static_cast<uint32_t>((neg->expires_at_ms > now ? neg->expires_at_ms - now : 0)/1000);
    res.rcode = neg->rcode;
    return res;
  }
  TRACE("cache MISS %s %u", qname.c_str(), qtype);

  // Laço iterativo
  string current_q = qname;
  vector<string> ns_queue = { start_ns_ip };
  unordered_set<string> tried_ns;
  int cname_hops = 0;
  int safety = 64;

  while (safety-- > 0)
  {
    if (ns_queue.empty())
    {
      res.kind = ResolveResult::Kind::ERROR;
      return res;
    }
    string ns_ip = ns_queue.back();

    ns_queue.pop_back();
    if (tried_ns.count(ns_ip))
      continue;
    tried_ns.insert(ns_ip);

    TRACE("query %s %u -> %s", current_q.c_str(), qtype, ns_ip.c_str());

    // consulta única
    auto q = buildQueryBytes(current_q, qtype, use_edns);
    DnsMessage msg; bool via_tcp = false;

    if (!sendOnce(ns_ip, q, timeout_ms, msg, via_tcp))
    {
      TRACE("timeout/erro em %s", ns_ip.c_str());
      continue;
    }

    // decisão central
    Decision d = analyzeResponse(msg, current_q, qtype, start_ns_ip, use_edns, timeout_ms);

    res.rcode = d.rcode;
    TRACE("rcode=%u", d.rcode);

    switch (d.kind)
    {
      case Decision::Kind::FINAL_OK:
      {
        TRACE("FINAL_OK %s %u (rr=%zu)", current_q.c_str(), qtype, d.rrset.size());
        putPositiveCache(current_q, qtype, d.rrset);
        if (daemon_.isAvailable())
        {
          auto rrset_cache = toRRsetForCache(d.rrset);

          daemon_.putPositive(current_q, qtype, minTTL(d.rrset), rrset_cache);
        }
        res.kind = ResolveResult::Kind::OK; res.ttl = minTTL(d.rrset);
        res.rrset = toRRsetForCache(d.rrset);
        return res;
      }
      case Decision::Kind::FINAL_NXDOMAIN:
      {
        TRACE("FINAL_NXDOMAIN ttl=%u", d.negative_ttl.value_or(60));
        putNegativeCache(current_q, qtype, /*is_nxdomain=*/true, d.negative_ttl);
        if (daemon_.isAvailable())
        {
          daemon_.putNegative(current_q, qtype, d.negative_ttl.value_or(60), 3);
        }
        res.kind = ResolveResult::Kind::NXDOMAIN; res.ttl = d.negative_ttl.value_or(60u);
        return res;
      }
      case Decision::Kind::FINAL_NODATA:
      {
        TRACE("FINAL_NODATA ttl=%u", d.negative_ttl.value_or(60));
        putNegativeCache(current_q, qtype, /*is_nxdomain=*/false, d.negative_ttl);
        if (daemon_.isAvailable())
        {
          daemon_.putNegative(current_q, qtype, d.negative_ttl.value_or(60), 0);
        }
        res.kind = ResolveResult::Kind::NODATA; res.ttl = d.negative_ttl.value_or(60u);
        return res;
      }
      case Decision::Kind::CNAME:
      {
        TRACE("CNAME %s -> %s", current_q.c_str(), d.cname_target.c_str());
        current_q = d.cname_target;
        if (++cname_hops > 10)
        {
          res.kind = ResolveResult::Kind::ERROR;
          return res;
        }
        tried_ns.clear();
        ns_queue.clear();
        ns_queue.push_back(ns_ip);
        continue;
      }
      case Decision::Kind::REFERRAL:
      {
        TRACE("REFERRAL ns_names=%zu glue_ips=%zu", d.next_ns_names.size(), d.next_ns_ips.size());

        vector<string> next_ns = d.next_ns_ips;

        if (next_ns.empty() && !d.next_ns_names.empty())
        {
          for (const auto& nsname : d.next_ns_names)
          {
            auto ips = resolveHostIPs(start_ns_ip, nsname, use_edns, timeout_ms, /*depth_budget=*/3);
           
            next_ns.insert(next_ns.end(), ips.begin(), ips.end());
          }
        }
        if (!next_ns.empty())
        {
          tried_ns.clear();
          ns_queue = move(next_ns);
          continue;
        }
        TRACE("REFERRAL sem NS útil, tentando próximo");
        continue;
      }
      case Decision::Kind::RETRY:
      default:
        TRACE("RETRY próximo NS");
        continue;
    }
  }

  res.kind = ResolveResult::Kind::ERROR;
  return res;
}
