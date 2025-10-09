#include "cache.h"
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <sstream>
#include <cctype>
#include <atomic>
#include <cstdio>
#include <chrono>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  static void closesock(int s){ closesocket(s); }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  static void closesock(int s){ close(s); }
#endif

static atomic<bool> running{true};
static mutex mtx;
static DnsCache g_cache(50, 50);

static uint64_t
nowMs()
{
  using namespace chrono;
  return duration_cast<milliseconds>(chrono::steady_clock::now().time_since_epoch()).count();
}

static string
toLower(const string& s)
{
  string r=s;

  for (auto& c: r)
    c = static_cast<char>(std::tolower((unsigned char)c));
  if (!r.empty() && r.back()=='.')
    r.pop_back();
  return r;
}

static string
hexEncode(const vector<uint8_t>& v)
{
  static const char* H = "0123456789abcdef";
  string out; out.reserve(v.size()*2);

  for (auto b: v)
  {
    out.push_back(H[b>>4]);
    out.push_back(H[b&0xF]);
  }
  return out;
}

static vector<uint8_t>
hexDecode(const string& s)
{
  vector<uint8_t> out;
  
  if (s.size()%2)
    return out;
  out.reserve(s.size()/2);

  auto val=[&](char c)->int
  {
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
  };

  for (size_t i=0;i<s.size();i+=2)
  {
    int hi=val(s[i]), lo=val(s[i+1]);

    if (hi<0||lo<0)
    {
      out.clear();
      return out;
    }
    out.push_back(static_cast<uint8_t>((hi<<4)|lo));
  }
  return out;
}

static bool
sendLine(int fd, const string& line)
{
  string l = line; l.push_back('\n');

#ifdef _WIN32
  int sent = ::send(fd, l.c_str(), (int)l.size(), 0);
  return sent == (int)l.size();
#else
  ssize_t sent = ::send(fd, l.data(), l.size(), 0);
  return sent == (ssize_t)l.size();
#endif
}

static bool
recvLine(int fd, string& out)
{
  out.clear();

  char c;

  while (true)
  {
#ifdef _WIN32
    int r = ::recv(fd, &c, 1, 0);
#else
    ssize_t r = ::recv(fd, &c, 1, 0);
#endif
    if (r<=0) return false;
    if (c=='\n') break;
    if (c!='\r') out.push_back(c);
    if (out.size()>8192) return false;
  }
  return true;
}

static void
handle_client(int fd)
{
  while (running)
  {
    string line;

    if (!recvLine(fd, line))
      break;

    istringstream iss(line);
    string cmd; iss >> cmd;

    if (cmd.empty())
      break;

    if (cmd=="STATUS")
    {
      lock_guard<mutex> lock(mtx);
      uint64_t now = nowMs();

      g_cache.purgeExpired(now);
      // Não temos contadores públicos; esta é uma resposta simples.
      sendLine(fd, "OK cache_daemon 50/50");
    }

    else if (cmd=="GET")
    {
      string name;
      unsigned type;

      if (!(iss>>name>>type))
      {
        sendLine(fd,"ERR bad GET");
        continue;
      }
      name = toLower(name);

      CacheKey key{name, (uint16_t)type, 1};
      lock_guard<mutex> lock(mtx);
      uint64_t now = nowMs();

      g_cache.purgeExpired(now);
      if (auto pos = g_cache.getPositive(key, now))
      {
        // POS <ttl_restante> <n>
        uint32_t ttl = (pos->expires_at_ms>now)? (uint32_t)((pos->expires_at_ms-now)/1000):0;
        
        sendLine(fd, "POS "+to_string(ttl)+" "+to_string(pos->rrset.size()));
        for (const auto& rr: pos->rrset)
        {
          sendLine(fd, to_string(rr.type)+" "+to_string(rr.rrclass)+" "+to_string(rr.ttl)+" "+hexEncode(rr.rdata));
        }
      }
      else if (auto neg = g_cache.getNegative(key, now))
      {
        uint32_t ttl = (neg->expires_at_ms>now)? (uint32_t)((neg->expires_at_ms-now)/1000):0;

        sendLine(fd, "NEG "+to_string(ttl)+" "+to_string(neg->rcode));
      }
      else
      {
        sendLine(fd, "NOTFOUND");
      }
    }
    else if (cmd=="PUTP")
    {
      string name;
      unsigned type;
      unsigned ttl;
      unsigned n;

      if (!(iss>>name>>type>>ttl>>n))
      {
        sendLine(fd,"ERR bad PUTP");
        continue;
      }
      name = toLower(name);

      PositiveEntry pe;
      uint64_t now = nowMs();

      pe.expires_at_ms = now + (uint64_t)ttl*1000ull;
      pe.rcode = 0;
      pe.rrset.reserve(n);
      for (unsigned i=0;i<n;++i)
      {
        string line2;

        if (!recvLine(fd, line2))
        {
          sendLine(fd,"ERR bad PUTP lines");
          goto done;
        }

        istringstream is2(line2);
        unsigned t,c,rrttl;
        string hex; 

        if (!(is2>>t>>c>>rrttl>>hex))
        {
          sendLine(fd,"ERR bad RR line");
          goto done;
        }

        RR r;

        r.name = name;
        r.type=(uint16_t)t;
        r.rrclass=(uint16_t)c;
        r.ttl=rrttl;
        r.rdata=hexDecode(hex);
        pe.rrset.push_back(move(r));
      }
      {
        lock_guard<mutex> lock(mtx);

        g_cache.putPositive(CacheKey{name,(uint16_t)type,1}, move(pe), now);
      }
      sendLine(fd, "OK");
    }
    else if (cmd=="PUTN")
    {
      string name;
      unsigned type;
      unsigned ttl;
      unsigned rcode;

      if (!(iss>>name>>type>>ttl>>rcode))
      {
        sendLine(fd,"ERR bad PUTN");
        continue;
      }
      name = toLower(name);

      NegativeEntry ne;
      uint64_t now = nowMs();

      ne.expires_at_ms = now + (uint64_t)ttl*1000ull;
      ne.rcode = (uint16_t)rcode;
      ne.kind = (rcode==3)? NegKind::NXDOMAIN : NegKind::NODATA;
      {
        lock_guard<mutex> lock(mtx);
        g_cache.putNegative(CacheKey{name,(uint16_t)type,1}, move(ne), now);
      }
      sendLine(fd, "OK");
    }
    else if (cmd=="QUIT" || cmd=="EXIT")
    {
      sendLine(fd, "BYE");
      break;
    }
    else
    {
      sendLine(fd, "ERR unknown");
    }
  }
done:
  closesock(fd);
}

int
main(int argc, char**)
{
#ifdef _WIN32
  WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif

  int srv = ::socket(AF_INET, SOCK_STREAM, 0);

  if (srv<0)
  {
    perror("socket");
    return 1;
  }

  sockaddr_in addr{};
  addr.sin_family=AF_INET;
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_port = htons(5353);

  int yes=1;

  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
  if (bind(srv, (sockaddr*)&addr, sizeof(addr))!=0)
  {
    perror("bind 127.0.0.1:5353");
    return 2;
  }
  if (listen(srv, 16)!=0)
  {
    perror("listen");
    return 3;
  }

  fprintf(stderr, "[cache_daemon] listening on 127.0.0.1:5353\n");

  while (running)
  {
    sockaddr_in cli{};
    socklen_t slen = sizeof(cli);
    int fd = ::accept(srv, (sockaddr*)&cli, &slen);
    if (fd<0)
      continue;
    thread(handle_client, fd).detach();
  }
  closesock(srv);
#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}
