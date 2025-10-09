#pragma once
#include "cache.h"
#include <string>
#include <vector>
#include <optional>

struct DaemonGetResult
{
  enum class Kind { NOTFOUND, POSITIVE, NEGATIVE, ERROR } kind = Kind::ERROR;
  std::vector<RR> rrset;  // quando POSITIVE
  uint32_t ttl = 0;       // ttl remanescente
  uint16_t rcode = 0;     // 3 para NXDOMAIN, 0 para NODATA
};

class CacheDaemonClient
{
public:
  CacheDaemonClient() = default;
  bool connectOnce(int timeout_ms = 200);
  bool isAvailable() const
  {
    return available_;
  }

  std::optional<DaemonGetResult> get(const std::string& name_norm, uint16_t qtype);
  bool putPositive(const std::string& name_norm, uint16_t qtype, uint32_t ttl, const std::vector<RR>& rrset);
  bool putNegative(const std::string& name_norm, uint16_t qtype, uint32_t ttl, uint16_t rcode);

private:
  bool available_ = false;
  int sock_ = -1;
  bool sendLine(const std::string& s);
  bool recvLine(std::string& out);
  bool ensure();
  void close_();
};
