#include "cache_client.h"
#include <sstream>
#include <cctype>

using namespace std;

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

// -- helpers hex
static string
hexEncode(const vector<uint8_t>& v)
{
  static const char* H="0123456789abcdef";
  string o;

  o.reserve(v.size()*2);

  for (auto b: v)
  {
    o.push_back(H[b>>4]);
    o.push_back(H[b&0xF]);
  }
  return o;
}

static vector<uint8_t>
hexDecode(const string& s)
{
  vector<uint8_t> out;
  
  out.reserve(s.size()/2);
  
  auto val=[&](char c)->int
  {
    if (c>='0'&&c<='9')
      return c-'0';
    if (c>='a'&&c<='f')
      return c-'a'+10;
    if (c>='A'&&c<='F')
      return c-'A'+10;
    return -1;
  };

  if (s.size()%2)
    return {};

  for (size_t i=0;i<s.size(); i+=2)
  {
    int hi=val(s[i]), lo=val(s[i+1]);

    if (hi<0||lo<0)
      return {};
    out.push_back((uint8_t)((hi<<4)|lo));
  }
  return out;
}

// -- I/O de linha
bool
CacheDaemonClient::sendLine(const string& s)
{
  string line = s;

  line.push_back('\n');

#ifdef _WIN32
  int sent = ::send(sock_, line.c_str(), (int)line.size(), 0);
  return sent == (int)line.size();
#else
  ssize_t sent = ::send(sock_, line.data(), line.size(), 0);
  return sent == (ssize_t)line.size();
#endif
}

bool
CacheDaemonClient::recvLine(string& out)
{
  out.clear();

  char c;

  while (true)
  {
#ifdef _WIN32
    int r = ::recv(sock_, &c, 1, 0);
#else
    ssize_t r = ::recv(sock_, &c, 1, 0);
#endif
    if (r<=0) return false;
    if (c=='\n') break;
    if (c!='\r') out.push_back(c);
    if (out.size()>8192) return false;
  }
  return true;
}

void
CacheDaemonClient::close_()
{
  if (sock_>=0)
  {
    closesock(sock_);
    sock_=-1;
  }
  available_ = false;
}

bool
CacheDaemonClient::ensure()
{ 
  return available_ && sock_>=0;
}

bool
CacheDaemonClient::connectOnce(int /*timeout_ms*/)
{
#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(2,2), &wsa);
#endif
  int s = ::socket(AF_INET, SOCK_STREAM, 0);

  if (s<0)
    return false;

  sockaddr_in addr{};

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_port = htons(5353);

  if (::connect(s, (sockaddr*)&addr, sizeof(addr))!=0)
  {
    closesock(s);
    return false;
  }
  sock_ = s;
  available_ = true;

  // ping STATUS para validar
  if (!sendLine("STATUS"))
  {
    close_();
    return false;
  }
  
  string line;

  if (!recvLine(line))
  {
    close_();
    return false;
  }
  return true;
}

optional<DaemonGetResult>
CacheDaemonClient::get(const string& name_norm, uint16_t qtype)
{
  if (!ensure())
    return nullopt;
  if (!sendLine("GET " + name_norm + " " + std::to_string(qtype)))
  {
    close_();
    return nullopt;
  }

  string l;

  if (!recvLine(l))
  {
    close_();
    return nullopt;
  }

  istringstream is(l);
  string tag;

  is >> tag;

  DaemonGetResult out;

  if (tag=="NOTFOUND")
  {
    out.kind = DaemonGetResult::Kind::NOTFOUND;
    return out;
  }
  if (tag=="NEG")
  {
    unsigned ttl, rcode;

    if (!(is>>ttl>>rcode))
    {
      out.kind=DaemonGetResult::Kind::ERROR;
      return out;
    }
    out.kind = DaemonGetResult::Kind::NEGATIVE;
    out.ttl=ttl;
    out.rcode=(uint16_t)rcode;
    return out;
  }
  if (tag=="POS")
  {
    unsigned ttl, n;
    if (!(is>>ttl>>n))
    {
      out.kind=DaemonGetResult::Kind::ERROR;
      return out;
    }
    out.kind = DaemonGetResult::Kind::POSITIVE;
    out.ttl = ttl;
    out.rrset.reserve(n);
    for (unsigned i=0;i<n;++i)
    {
      if (!recvLine(l))
      {
        out.kind=DaemonGetResult::Kind::ERROR;
        return out;
      }

      istringstream is2(l);
      unsigned t,c,rrttl;
      string hex;

      if (!(is2>>t>>c>>rrttl>>hex))
      {
        out.kind=DaemonGetResult::Kind::ERROR;
        return out;
      }

      RR r;

      r.name = name_norm;
      r.type=(uint16_t)t;
      r.rrclass=(uint16_t)c;
      r.ttl=rrttl;
      r.rdata=hexDecode(hex);
      out.rrset.push_back(move(r));
    }
    return out;
  }
  out.kind = DaemonGetResult::Kind::ERROR;
  return out;
}

bool
CacheDaemonClient::putPositive(const string& name_norm, uint16_t qtype, uint32_t ttl, const vector<RR>& rrset)
{
  if (!ensure())
    return false;
  if (!sendLine("PUTP " + name_norm + " " + std::to_string(qtype) + " " + std::to_string(ttl) + " " + std::to_string(rrset.size())))
    {
      close_();
      return false;
    }
  for (const auto& r: rrset)
  {
    string line = to_string(r.type)+" "+to_string(r.rrclass)+" "+to_string(r.ttl)+" "+hexEncode(r.rdata);

    if (!sendLine(line))
    {
      close_();
      return false;
    }
  }
  string ok;
  if (!recvLine(ok))
  {
    close_();
    return false;
  }
  return ok=="OK";
}

bool
CacheDaemonClient::putNegative(const string& name_norm, uint16_t qtype, uint32_t ttl, uint16_t rcode)
{
  if (!ensure())
    return false;
  if (!sendLine("PUTN " + name_norm + " " + std::to_string(qtype) + " " + std::to_string(ttl) + " " + std::to_string(rcode)))
    {
      close_();
      return false;
    }

  string ok;
  
  if (!recvLine(ok))
  {
    close_();
    return false;
  }
  return ok=="OK";
}
