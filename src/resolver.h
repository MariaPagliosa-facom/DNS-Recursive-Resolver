#pragma once
#include <string>
#include <optional>
#include <cstdint>
#include <vector>
#include <unordered_set>
#include <cstdarg>
#include "cache.h"
#include "dns_wire.h"
#include "cache_client.h"
#include "transport_tls.h"

// Resultado final "alto nível" para o modo iterativo + cache
struct ResolveResult
{
  enum class Kind { OK, NXDOMAIN, NODATA, ERROR } kind = Kind::ERROR;
  uint32_t ttl = 0;            // TTL efetivo (segundos)
  vector<RR> rrset;            // RRset final quando OK
  uint16_t rcode = 0;          // RCODE da última resposta analisada
};

// Resultado da consulta “1 salto” (direto ao NS), útil para debug
struct SingleQueryResult
{
  bool ok = false;
  bool via_tcp = false;     // true quando usou TCP (ou TLS/DoT)
  uint16_t rcode = 0;
  DnsMessage message;       // já parseada
};

class Resolver
{
public:
  Resolver() = default;

  // ---- DoT/DNS mode ----
  enum class Mode { DNS, DOT };
  void setMode(Mode m) { mode_ = m; }
  void setSNI(const string& s) { sni_ = s; }
  void setDotInsecure(bool b) { dot_insecure_ = b; }

  // Ativa/desativa trace no console (stderr)
  void setTrace(bool on) { trace_ = on; }

  // Consulta direta (1 salto): 
  // - DNS: UDP e fallback TCP se TC=1
  // - DoT: TLS/853 com SNI e validação de certificado
  optional<SingleQueryResult> singleQueryTo(const string& ns_ip,
                                            const string& qname,
                                            const string& qtype,
                                            bool use_edns = true,
                                            int timeout_ms = 3000);

  // Resolução iterativa + cache (começa do NS informado; idealmente um root)
  optional<ResolveResult> resolveRecursive(const string& start_ns_ip,
                                            const string& qname_in,
                                            const string& qtype_in,
                                            bool use_edns = true,
                                            int timeout_ms = 3000);

private:
  DnsCache cache_{50, 50};
  bool trace_ = false;

  // modo de transporte
  Mode mode_ = Mode::DNS;
  string sni_;
  bool dot_insecure_ = false;

  // cache daemon (opcional): se disponível, preferimos ele
  CacheDaemonClient daemon_;
  bool tried_daemon_ = false;

  // ------------ Helpers básicos ------------
  uint16_t parseType(const string& qtype);
  uint64_t nowMs() const;

  vector<uint8_t> buildQueryBytes(const string& qname, uint16_t qtype, bool use_edns) const;
  bool sendOnce(const string& ns_ip,
                const vector<uint8_t>& q,
                int timeout_ms,
                DnsMessage& out,
                bool& via_tcp);

  static uint16_t getRCODE(const DnsMessage& m);
  static bool hasTC(const DnsMessage& m);

  static bool hasAnswerTypeForName(const DnsMessage& m, const string& qname, uint16_t qtype);
  static vector<DnsRR> collectAnswerTypeForName(const DnsMessage& m, const string& qname, uint16_t qtype);
  static optional<string> findCNAMEtargetFor(const DnsMessage& m, const string& qname);
  static vector<string> collectNSNames(const DnsMessage& m);
  static vector<string> collectGlueIPsFor(const DnsMessage& m, const unordered_set<string>& ns_names);
  static optional<uint32_t> negativeTTL_from_SOA(const DnsMessage& m);

  // Resolve A/AAAA de um hostname (p/ NS sem glue)
  vector<string> resolveHostIPs(const string& start_ns_ip,
                                          const string& host,
                                          bool use_edns,
                                          int timeout_ms,
                                          int depth_budget);

  // Cache: grava positivo/negativo
  void putPositiveCache(const string& qname_norm, uint16_t qtype, const vector<DnsRR>& rrset);
  void putNegativeCache(const string& qname_norm, uint16_t qtype,
                        bool is_nxdomain, optional<uint32_t> neg_ttl_opt);

  // Conversões/TTL
  static vector<RR> toRRsetForCache(const vector<DnsRR>& v);
  static uint32_t minTTL(const vector<DnsRR>& v);

  // ------------ Decisão centralizada sobre uma resposta ------------
  struct Decision {
    enum class Kind { FINAL_OK, FINAL_NXDOMAIN, FINAL_NODATA, CNAME, REFERRAL, RETRY } kind = Kind::RETRY;
    uint16_t rcode = 0;

    // FINAL_OK
    vector<DnsRR> rrset;

    // FINAL_NX/NODATA
    optional<uint32_t> negative_ttl;

    // CNAME
    string cname_target; // normalizado

    // REFERRAL
    vector<string> next_ns_ips;   // IPs de glue (se houver)
    vector<string> next_ns_names; // nomes de NS (para resolver IP se não houver glue)
  };

  Decision analyzeResponse(const DnsMessage& m,
                           const string& qname_norm,
                           uint16_t qtype,
                           const string& start_ns_ip,
                           bool use_edns,
                           int timeout_ms);

  // helper de trace
  void TRACE(const char* fmt, ...) const;
};
