#include "transport.h"
#include <cstring>
#include <string>
#include <vector>
#include <cerrno>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socklen_t = int;
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
#endif

// Utilitário: fecha socket portátil
static void
closesock(int fd)
{
#ifdef _WIN32
  closesocket(fd);
#else
  close(fd);
#endif
}

static bool
set_timeouts(int fd, int timeout_ms)
{
#ifdef _WIN32
  DWORD t = timeout_ms;

  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t)) != 0)
    return false;
  if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof(t)) != 0)
    return false;
#else
  timeval tv;
  tv.tv_sec  = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
    return false;
  if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
    return false;
#endif
  return true;
}

static int
gai_family_for_ip(const string& ip)
{
  // heurística simples: tem ':' -> IPv6, senão IPv4
  return (ip.find(':') != string::npos) ? AF_INET6 : AF_INET;
}

vector<uint8_t>
sendUDP(const string& server_ip, uint16_t port,
        const vector<uint8_t>& payload, int timeout_ms)
{
  vector<uint8_t> out;
  addrinfo hints{};
  
  hints.ai_family   = gai_family_for_ip(server_ip);
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;

  addrinfo* res = nullptr;
  const string port_s = to_string(port);

  if (getaddrinfo(server_ip.c_str(), port_s.c_str(), &hints, &res) != 0 || !res)
  {
    return out;
  }

  int fd = -1;

  for (addrinfo* ai = res; ai; ai = ai->ai_next)
  {
    fd = static_cast<int>(::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
    if (fd < 0)
      continue;
    if (!set_timeouts(fd, timeout_ms))
    {
      closesock(fd);
      fd = -1;
      continue;
    }

    ssize_t sent = ::sendto(fd, reinterpret_cast<const char*>(payload.data()),
                            static_cast<int>(payload.size()), 0,
                            ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen));

    if (sent < 0 || static_cast<size_t>(sent) != payload.size())
    {
      closesock(fd);
      fd = -1;
      continue;
    }

    // buffer generoso para DNS (com EDNS)
    vector<uint8_t> buf(4096);
    sockaddr_storage from{};
    socklen_t fromlen = sizeof(from);
    ssize_t rcv = ::recvfrom(fd, reinterpret_cast<char*>(buf.data()),
                             static_cast<int>(buf.size()), 0,
                             reinterpret_cast<sockaddr*>(&from), &fromlen);

    if (rcv > 0)
    {
      out.assign(buf.begin(), buf.begin() + rcv);
      closesock(fd);
      freeaddrinfo(res);
      return out;
    }

    closesock(fd);
    fd = -1;
  }

  if (res)
    freeaddrinfo(res);
  return out; // vazio indica falha/timeout
}

static bool
write_all(int fd, const uint8_t* data, size_t n)
{
  size_t off = 0;

  while (off < n)
  {
#ifdef _WIN32
    int w = ::send(fd, reinterpret_cast<const char*>(data + off), static_cast<int>(n - off), 0);
#else
    ssize_t w = ::send(fd, data + off, n - off, 0);
#endif
    if (w <= 0)
      return false;
    off += static_cast<size_t>(w);
  }
  return true;
}

static bool
read_n(int fd, uint8_t* data, size_t n)
{
  size_t off = 0;

  while (off < n)
  {
#ifdef _WIN32
    int r = ::recv(fd, reinterpret_cast<char*>(data + off), static_cast<int>(n - off), 0);
#else
    ssize_t r = ::recv(fd, data + off, n - off, 0);
#endif
    if (r <= 0) return false;
    off += static_cast<size_t>(r);
  }
  return true;
}

vector<uint8_t>
sendTCP(const string& server_ip, uint16_t port,
        const vector<uint8_t>& payload, int timeout_ms)
{
  vector<uint8_t> out;
  addrinfo hints{};

  hints.ai_family   = gai_family_for_ip(server_ip);
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  addrinfo* res = nullptr;
  const string port_s = to_string(port);

  if (getaddrinfo(server_ip.c_str(), port_s.c_str(), &hints, &res) != 0 || !res)
  {
    return out;
  }

  int fd = -1;

  for (addrinfo* ai = res; ai; ai = ai->ai_next)
  {
    fd = static_cast<int>(::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
    if (fd < 0)
      continue;

    if (!set_timeouts(fd, timeout_ms))
    { 
      closesock(fd);
      fd = -1;
      continue;
    }

    if (::connect(fd, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) != 0)
    {
      closesock(fd); fd = -1;
      continue;
    }

    // DNS/TCP: prefixo de 2 bytes com o tamanho
    uint16_t len = static_cast<uint16_t>(payload.size());
    uint8_t hdr[2] = { static_cast<uint8_t>((len >> 8) & 0xFF),
                       static_cast<uint8_t>(len & 0xFF) };

    if (!write_all(fd, hdr, 2) || !write_all(fd, payload.data(), payload.size()))
    {
      closesock(fd);
      fd = -1;
      continue;
    }

    // Lê prefixo 2 bytes (tamanho)
    uint8_t szbuf[2];

    if (!read_n(fd, szbuf, 2))
    {
      closesock(fd);
      fd = -1;
      continue;
    }

    uint16_t rlen = (static_cast<uint16_t>(szbuf[0]) << 8) | static_cast<uint16_t>(szbuf[1]);

    if (rlen == 0)
    {
      closesock(fd);
      fd = -1;
      continue;
    }

    out.resize(rlen);
    if (!read_n(fd, out.data(), rlen))
    {
      out.clear();
      closesock(fd);
      fd = -1;
      continue;
    }

    closesock(fd);
    freeaddrinfo(res);
    return out;
  }

  if (res) freeaddrinfo(res);
  return out; // vazio indica falha/timeout
}
