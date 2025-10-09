#include <iostream>
#include <string>
#include <algorithm>
#include "resolver.h"
#include "dns_wire.h"

static void
usage()
{
  cerr <<
    "Uso: tp1dns_cli --ns <ip> --name <qname> --qtype <A|AAAA|NS|MX|TXT|CNAME|SOA>\n"
    "                [--iter] [--trace] [--mode {dns,dot}] [--sni <hostname>] [--insecure-dot]\n"
    "\n"
    "Exemplos:\n"
    "  # Consulta direta (1 salto) via UDP/TCP\n"
    "  tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A\n"
    "\n"
    "  # Consulta direta (1 salto) via DoT (TLS/853) com SNI (recursivos públicos)\n"
    "  tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com\n"
    "  tp1dns_cli --ns 8.8.8.8 --name example.com --qtype AAAA --mode dot --sni dns.google\n"
    "  # (diagnóstico) ignorar validação de certificado: --insecure-dot\n"
    "\n"
    "  # Resolução iterativa + cache (começando em um root)\n"
    "  tp1dns_cli --ns 198.41.0.4 --name www.ufms.br --qtype A --iter --trace\n";
}

static string
toLower(string s)
{
  transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)tolower(c); });
  return s;
}

int
main(int argc, char** argv)
{
  string ns_ip, qname, qtype = "A";
  bool use_iter = false;
  bool use_trace = false;
  string mode = "dns";   // dns | dot
  string sni;            // obrigatório quando --mode dot
  bool insecure_dot = false;  // diagnóstico (não valide certificado)

  // Parse args
  for (int i = 1; i < argc; ++i)
  {
    string arg = argv[i];

    if (arg == "--ns" && i + 1 < argc)
      ns_ip = argv[++i];
    else if (arg == "--name" && i + 1 < argc)
      qname = argv[++i];
    else if (arg == "--qtype" && i + 1 < argc)
      qtype = argv[++i];
    else if (arg == "--iter")
      use_iter = true;
    else if (arg == "--trace")
      use_trace = true;
    else if (arg == "--mode" && i + 1 < argc)
      mode = toLower(argv[++i]);     // dns|dot
    else if (arg == "--sni"  && i + 1 < argc)
      sni  = argv[++i];
    else if (arg == "--insecure-dot")
      insecure_dot = true;
    else if (arg == "--help" || arg == "-h")
    {
      usage();
      return 0;
    }
  }

  if (ns_ip.empty() || qname.empty())
  {
    usage();
    return 1;
  }

  Resolver resolver;

  resolver.setTrace(use_trace);

  if (mode == "dot")
  {
    // DoT é aplicado apenas ao modo 1 salto (singleQueryTo).
    resolver.setMode(Resolver::Mode::DOT);
    resolver.setSNI(sni);
    resolver.setDotInsecure(insecure_dot);
    if (!use_iter && sni.empty())
    {
      cerr << "Erro: --mode dot requer --sni <hostname> (ex.: cloudflare-dns.com ou dns.google)\n";
      return 2;
    }
  }
  else
  {
    resolver.setMode(Resolver::Mode::DNS);
  }

  // Modo 1 salto (DNS ou DoT)
  if (!use_iter)
  {
    auto r = resolver.singleQueryTo(ns_ip, qname, qtype, /*use_edns=*/true, /*timeout_ms=*/3000);

    if (!r.has_value())
    {
      cerr << "Erro: sem resposta válida do servidor " << ns_ip << "\n";
      return 3;
    }

    const auto& m = r->message;

    cout << "--- Resultado (consulta direta ao NS) ---\n";
    if (mode == "dot")
    {
      cout << "Via servidor: " << ns_ip << " (TCP/TLS)\n";
    }
    else
    {
      cout << "Via servidor: " << ns_ip << (r->via_tcp ? " (TCP)\n" : " (UDP)\n");
    }

    cout << "RCODE=" << (m.header.flags & 0x000F)
         << " AA=" << ((m.header.flags & 0x0400) ? 1 : 0)
         << " TC=" << ((m.header.flags & 0x0200) ? 1 : 0)
         << "\n";
    cout << "Counts: QD=" << m.header.qdcount
         << " AN=" << m.header.ancount
         << " NS=" << m.header.nscount
         << " AR=" << m.header.arcount << "\n";

    if (!m.answers.empty())
    {
      cout << "Answers (primeiros 5):\n";
      for (size_t i = 0; i < m.answers.size() && i < 5; ++i)
      {
        const auto& rr = m.answers[i];

        cout << "  " << rr.name << "  TTL=" << rr.ttl << "  TYPE=" << rr.type;
        if (rr.type == dnstype::A || rr.type == dnstype::AAAA)
        {
          cout << "  " << rdataToIPString(rr) << "\n";
        }
        else if (rr.type == dnstype::CNAME || rr.type == dnstype::NS)
        {
          cout << "  -> " << rdataToDomainName(rr, m) << "\n";
        }
        else
        {
          cout << "  RDLEN=" << rr.rdata.size() << "\n";
        }
      }
    }
    if (!m.authorities.empty())
    {
      cout << "Authorities (primeiros 3):\n";
      for (size_t i = 0; i < m.authorities.size() && i < 3; ++i)
      {
        const auto& rr = m.authorities[i];

        cout << "  " << rr.name << "  TTL=" << rr.ttl << "  TYPE=" << rr.type << "\n";
      }
    }
    if (!m.additionals.empty())
    {
      cout << "Additionals (primeiros 3):\n";
      for (size_t i = 0; i < m.additionals.size() && i < 3; ++i)
      {
        const auto& rr = m.additionals[i];

        cout << "  " << rr.name << "  TTL=" << rr.ttl << "  TYPE=" << rr.type
                  << "  RDLEN=" << rr.rdata.size() << "\n";
      }
    }
    return 0;
  }


  // Modo iterativo + cache + daemon
  auto rr = resolver.resolveRecursive(ns_ip, qname, qtype, /*use_edns=*/true, /*timeout_ms=*/3000);

  if (!rr.has_value())
  {
    cerr << "Falha na resolução.\n";
    return 4;
  }

  cout << "--- Resultado (iterativo + cache) ---\n";
  cout << "RCODE=" << rr->rcode << "\n";

  switch (rr->kind)
  {
    case ResolveResult::Kind::OK:
      cout << "OK (TTL=" << rr->ttl << "s) RRset:\n";
      for (const auto& rrc : rr->rrset)
      {
        cout << "  " << rrc.name << "  TTL=" << rrc.ttl
             << "  TYPE=" << rrc.type
             << "  RDLEN=" << rrc.rdata.size() << "\n";
      }
      break;
    case ResolveResult::Kind::NXDOMAIN:
      cout << "NXDOMAIN (TTL=" << rr->ttl << "s)\n";
      break;
    case ResolveResult::Kind::NODATA:
      cout << "NODATA (TTL=" << rr->ttl << "s)\n";
      break;
    default:
      cout << "ERROR\n";
      break;
  }

  return 0;
}
