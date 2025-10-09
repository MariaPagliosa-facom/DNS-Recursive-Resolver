#include <iostream>
#include <string>
#include <sstream>
#include <vector>

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
  #include <unistd.h>
  static void closesock(int s){ close(s); }
#endif

static bool
sendLine(int fd, const string& s)
{
  string line = s; line.push_back('\n');
  
#ifdef _WIN32
  int sent = ::send(fd, line.c_str(), (int)line.size(), 0);
  return sent == (int)line.size();
#else
  ssize_t sent = ::send(fd, line.data(), line.size(), 0);
  return sent == (ssize_t)line.size();
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

static int
connect_daemon()
{
#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(2,2), &wsa);
#endif
  int s = ::socket(AF_INET, SOCK_STREAM, 0);

  if (s<0)
  {
    perror("socket");
    return -1;
  }
  sockaddr_in addr{};

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_port = htons(5353);
  if (::connect(s, (sockaddr*)&addr, sizeof(addr))!=0)
  {
    perror("connect 127.0.0.1:5353");
    closesock(s);
    return -1;
  }
  return s;
}

static void
usage()
{
  cerr << "Uso:\n";
  cerr << "  cachectl status\n";
  cerr << "  cachectl get <nome> <tipo>\n";
  cerr << "   ex.: cachectl get www.ufms.br A\n";
}

static string
qtype_to_num(const string& t)
{
  string u=t;
  for (auto& c: u)
    c = (char)toupper((unsigned char)c);
  if (u=="A")
    return "1";
  if (u=="NS")
    return "2";
  if (u=="CNAME")
    return "5";
  if (u=="SOA")
    return "6";
  if (u=="MX")
    return "15";
  if (u=="TXT")
    return "16";
  if (u=="AAAA")
    return "28";
  return u;
}

int
main(int argc, char** argv)
{
  if (argc < 2)
  {
    usage();
    return 1;
  }

  string cmd = argv[1];
  int fd = connect_daemon();

  if (fd<0)
  {
    cerr << "cache_daemon não está ativo.\n";
    return 2;
  }

  if (cmd == "status")
  {
    if (!sendLine(fd, "STATUS"))
      return 3;

    string l;

    if (!recvLine(fd, l))
      return 3;
    cout << l << "\n";
  }
  else if (cmd == "get")
  {
    if (argc < 4)
    {
      usage();
      return 1;
    }

    string name = argv[2];
    string tnum = qtype_to_num(argv[3]);

    if (!sendLine(fd, "GET " + name + " " + tnum))
      return 3;

    string l;
    
    if (!recvLine(fd, l))
      return 3;

    istringstream is(l);
    string tag;
    
    is >> tag;

    if (tag=="NOTFOUND")
    {
      cout << "NOTFOUND\n";
    }
    else if (tag=="NEG")
    {
      unsigned ttl, rcode;
      
      is >> ttl >> rcode;
      cout << "NEG ttl=" << ttl << " rcode=" << rcode << (rcode==3? " (NXDOMAIN)":" (NODATA)") << "\n";
    }
    else if (tag=="POS")
    {
      unsigned ttl, n;

      is >> ttl >> n;
      cout << "POS ttl=" << ttl << " rr=" << n << "\n";
      for (unsigned i=0;i<n;++i)
      {
        if (!recvLine(fd, l))
          return 3;
        cout << "  " << l << "\n"; // "TYPE CLASS TTL HEXRDATA"
      }
    }
    else
    {
      cout << "ERRO: " << l << "\n";
    }
  }
  else
  {
    usage();
    return 1;
  }
  sendLine(fd, "QUIT");
  closesock(fd);
  return 0;
}
