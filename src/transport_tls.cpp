#include "transport_tls.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cstdint>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  static void closesock(SOCKET s){ closesocket(s); }
  using socklen_t = int;
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <arpa/inet.h>
  static void closesock(int s){ close(s); }
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

using std::string;
using std::vector;

// Helpers de erro OpenSSL
static void
log_openssl_error(const char* where)
{
  unsigned long err;

  while ((err = ERR_get_error()) != 0)
  {
    char buf[256];

    ERR_error_string_n(err, buf, sizeof(buf));
    fprintf(stderr, "[dot] %s: %s\n", where, buf);
  }
}

// Sockets: timeouts de envio/recebimento (não cobre connect no POSIX puro)
static void set_timeouts(int fd, int timeout_ms)
{
#ifdef _WIN32
  DWORD tv = (DWORD)timeout_ms;

  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
  timeval tv{};
  tv.tv_sec  = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

// TCP connect (IPv4/IPv6) via getaddrinfo. Simples (bloqueante), com timeouts em send/recv.
static int
tcp_connect_gai(const string& host, uint16_t port, int timeout_ms)
{
  char port_s[16];

  snprintf(port_s, sizeof(port_s), "%u", (unsigned)port);

  struct addrinfo hints{};

  hints.ai_family = AF_UNSPEC;    // IPv4 e IPv6
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = 0;            // aceitar host numérico ou nome

  struct addrinfo* res = nullptr;
  int rc = getaddrinfo(host.c_str(), port_s, &hints, &res);

  if (rc != 0 || !res)
  {
    fprintf(stderr, "[dot] getaddrinfo(%s): %s\n", host.c_str(), gai_strerror(rc));
    return -1;
  }

  int fd = -1;

  for (auto ai = res; ai; ai = ai->ai_next)
  {
    fd = (int) ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0)
      continue;
    set_timeouts(fd, timeout_ms);
    if (::connect(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0)
    {
      // conectado
      freeaddrinfo(res);
      return fd;
    }
    closesock(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return -1;
}

// sendDoT: DNS over TLS (RFC 7858) — envia DNS/TCP (length-prefixed) dentro
// de um túnel TLS na porta 853. Retorna o payload DNS (sem os 2 bytes de len).
vector<uint8_t> sendDoT(const string& ns_ip,
                        uint16_t port,
                        const vector<uint8_t>& query,
                        const string& sni,
                        int timeout_ms,
                        bool insecure)
{
  vector<uint8_t> empty;

  // SNI obrigatório para recursivos públicos (dns.google, cloudflare-dns.com)
  if (sni.empty() || query.empty() || query.size() > 65535)
  {
    return empty;
  }

  // 1) Conexão TCP (bloqueante simples). Suporta IPv4/IPv6 e hostname/IP.
  int fd = tcp_connect_gai(ns_ip, port, timeout_ms);

  if (fd < 0)
  {
    fprintf(stderr, "[dot] connect failed %s:%u\n", ns_ip.c_str(), (unsigned)port);
    return empty;
  }

  // 2) Inicialização OpenSSL (camada TLS)
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx)
  {
    log_openssl_error("SSL_CTX_new");
    closesock(fd);
    return empty;
  }

  if (!insecure)
  {
    // Verifica o certificado do servidor contra o store do sistema.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(ctx);
    // ref ref: tentar diretório padrão de certs (Ubuntu/Debian)
    SSL_CTX_load_verify_locations(ctx, nullptr, "/etc/ssl/certs");
  }
  else
  {
    // Modo diagnóstico: NÃO valide o certificado
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  }

  SSL* ssl = SSL_new(ctx);
  if (!ssl)
  {
    log_openssl_error("SSL_new");
    SSL_CTX_free(ctx);
    closesock(fd);
    return empty;
  }

  // SNI — essencial para o servidor apresentar o certificado correto
  if (!SSL_set_tlsext_host_name(ssl, sni.c_str()))
  {
    log_openssl_error("SSL_set_tlsext_host_name");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesock(fd);
    return empty;
  }

  SSL_set_fd(ssl, fd);

  // 3) Handshake TLS
  if (SSL_connect(ssl) != 1)
  {
    log_openssl_error("SSL_connect");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesock(fd);
    return empty;
  }

  // 4) Verificação de hostname do certificado (se não-inseguro)
  if (!insecure)
  {
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert)
    {
      fprintf(stderr, "[dot] no peer certificate\n");
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      closesock(fd);
      return empty;
    }
    // Checa se CN/SAN casa com o SNI informado
    int ok = X509_check_host(cert, sni.c_str(), sni.size(), 0, nullptr);

    X509_free(cert);
    if (ok != 1)
    {
      fprintf(stderr, "[dot] X509_check_host failed for SNI=%s\n", sni.c_str());
      log_openssl_error("X509_check_host");
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      closesock(fd);
      return empty;
    }
  }

  // 5) Framing DNS/TCP dentro do TLS: 2 bytes big-endian + payload
  uint16_t qlen = (uint16_t)query.size();
  uint8_t head[2] = { (uint8_t)(qlen >> 8), (uint8_t)(qlen & 0xFF) };
  int w = SSL_write(ssl, head, 2);

  if (w != 2)
  {
    log_openssl_error("SSL_write(len)");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesock(fd);
    return empty;
  }

  int w2 = SSL_write(ssl, query.data(), (int)query.size());

  if (w2 != (int)query.size())
  {
    log_openssl_error("SSL_write(query)");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesock(fd);
    return empty;
  }

  // 6) Ler os 2 bytes de tamanho da resposta
  uint8_t lenbuf[2];
  int r = SSL_read(ssl, lenbuf, 2);

  if (r != 2)
  {
    log_openssl_error("SSL_read(len)");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesock(fd);
    return empty;
  }

  uint16_t resp_len = (uint16_t)((lenbuf[0] << 8) | lenbuf[1]);

  if (resp_len == 0)
  {
    fprintf(stderr, "[dot] resp_len=0\n");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesock(fd);
    return empty;
  }

  // 7) Ler exatamente resp_len bytes do payload DNS
  vector<uint8_t> out(resp_len);
  size_t got = 0;

  while (got < resp_len)
  {
    int n = SSL_read(ssl, out.data() + got, (int)(resp_len - got));

    if (n <= 0)
    {
      log_openssl_error("SSL_read(payload)");
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      closesock(fd);
      return empty;
    }
    got += (size_t)n;
  }

  // 8) Fechar tudo
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  closesock(fd);

  return out;
}
