#include "dns_wire.h"
#include <algorithm>
#include <random>
#include <stdexcept>
#include <arpa/inet.h> // em Linux. No Windows, esse helper não é usado (só formatação manual).

// Helpers de leitura/escrita
// Empurram um uint16_t e um uint32_t para o vetor em ordem de rede (BIG-ENDIAN)
void
push_u16(vector<uint8_t>& buf, uint16_t v)
{
  buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

void
push_u32(vector<uint8_t>& buf, uint32_t v)
{
  buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
  buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

// – Lê uint16_t/uint32_t de b a partir de off (big-endian),
// avança off e retorna false se não houver bytes suficientes.
bool
read_u16(const vector<uint8_t>& b, size_t& off, uint16_t& out)
{
  if (off + 2 > b.size())
    return false;
  out = (static_cast<uint16_t>(b[off]) << 8) | static_cast<uint16_t>(b[off+1]);
  off += 2;
  return true;
}

bool
read_u32(const vector<uint8_t>& b, size_t& off, uint32_t& out)
{
  if (off + 4 > b.size())
    return false;
  out = (static_cast<uint32_t>(b[off])   << 24) |
        (static_cast<uint32_t>(b[off+1]) << 16) |
        (static_cast<uint32_t>(b[off+2]) << 8 ) |
         static_cast<uint32_t>(b[off+3]);
  off += 4;
  return true;
}

// Converte "www.ufms.br" para [3]'www'[4]'ufms'[2]'br'[0]
bool
encode_name(const string& name, vector<uint8_t>& out)
{
  if (name.empty() || name == ".") // nomes vazios significam raiz
  {
    out.push_back(0);
    return true;
  }

  size_t start = 0;

  // Dividir o nome nos rótulos (entre pontos), escrever len e label pra cada,
  // validar len <= 63 e terminar com 0
  while (start < name.size())
  {
    size_t dot = name.find('.', start);
    size_t end = (dot == string::npos) ? name.size() : dot;
    size_t len = end - start;

    if (len > 63)
      return false; // rótulo DNS <= 63 bytes
    out.push_back(static_cast<uint8_t>(len));
    for (size_t i = start; i < end; ++i)
      out.push_back(static_cast<uint8_t>(name[i]));
    if (dot == string::npos) 
      break;
    start = dot + 1;
  }
  out.push_back(0); // terminador
  return true;
}

// Decodificador de nomes: suporta compressão por ponteiros (RFC 1035).
// cur é o cursor “real”; off é a posição do chamador (avança diferente quando há ponteiro).
// jumped/jump_end controlam o retorno ao fluxo original após seguir um ponteiro.
// jumps limita loops maliciosos (proteção).
bool
decode_name(const vector<uint8_t>& b, size_t& off, string& out)
{
  out.clear();

  size_t cur = off;
  bool jumped = false;
  size_t jump_end = 0; // onde retomar se bater ponteiro
  int jumps = 0; // Evitar loop de ponteiros maliciosos

  // Evitar loop de ponteiros maliciosos
  while (true)
  {
    if (cur >= b.size())
      return false;

    uint8_t len = b[cur];

    // Ponteiro?
    if ((len & 0xC0) == 0xC0)
    {
      if (cur + 1 >= b.size())
        return false;

      uint16_t ptr = ((static_cast<uint16_t>(len & 0x3F) << 8) |
                      static_cast<uint16_t>(b[cur+1]));

      if (!jumped)
      {
        jump_end = cur + 2; // onde continuar depois
        jumped = true;
      }
      cur = ptr;
      if (++jumps > 16)
        return false; // proteção
      continue;
    }

    // Fim do nome
    if (len == 0)
    {
      cur += 1;
      break;
    }

    // Label normal
    if (cur + 1 + len > b.size())
      return false;
    if (!out.empty())
      out.push_back('.');
    for (size_t i = 0; i < len; ++i)
      out.push_back(static_cast<char>(b[cur + 1 + i]));
    cur += 1 + len;
  }

  // Avança o 'off' apenas se não houve salto; se houve, volta ao ponto após o ponteiro
  off = jumped ? jump_end : cur;
  return true;
}

// Prepara o buffer (capacidade inicial)
vector<uint8_t>
buildQuery(const string& qname, uint16_t qtype, bool use_edns)
{
  vector<uint8_t> buf;

  buf.reserve(512);

  // ID aleatório
  static random_device rd;
  static mt19937 gen(rd());
  uint16_t id = static_cast<uint16_t>(gen());

  // Flags: RD=0 (resolver iterativo), QR=0 (query)
  uint16_t flags = 0x0000;
  // Se depois quiser RD=1 para simular stub, trocar aqui (flags |= 0x0100).

  // Teremos 1 Question. As outras seções ficam 0. Se use_edns, haverá 1 RR OPT na Additional.
  uint16_t qdcount = 1;
  uint16_t ancount = 0, nscount = 0, arcount = use_edns ? 1 : 0;

  // Escreve o Header (12 bytes) no buffer
  push_u16(buf, id);
  push_u16(buf, flags);
  push_u16(buf, qdcount);
  push_u16(buf, ancount);
  push_u16(buf, nscount);
  push_u16(buf, arcount);

  // Question
  if (!encode_name(qname, buf))
    throw runtime_error("encode_name: label > 63 bytes");
  push_u16(buf, qtype);
  push_u16(buf, 1 /*IN*/);

  // EDNS(0) OPT RR (Additional)
  if (use_edns)
  {
    // NAME = root (0)
    buf.push_back(0x00);
    // TYPE = 41 (OPT)
    push_u16(buf, 41);
    // CLASS = tamanho máximo de UDP aceito
    // 1232 é um bom valor moderno para evitar fragmentação (padrão comum).
    push_u16(buf, 1232);

    // TTL (32 bits) = Extended RCODE (8) | EDNS Version (8) | Z flags (16)
    push_u32(buf, 0);

    // RDLENGTH = 0 (sem opções)
    push_u16(buf, 0);
  }

  return buf; // Retorna os bytes da query prontos para enviar
}

// Lê QNAME, QTYPE, QCLASS. Usa decode_name (com ponteiros) e avança off
static bool
parse_question(const vector<uint8_t>& b, size_t& off, DnsQuestion& q)
{
  if (!decode_name(b, off, q.qname))
    return false;
  if (!read_u16(b, off, q.qtype))
    return false;
  if (!read_u16(b, off, q.qclass))
    return false;
  return true;
}

// Lê NAME (com compressão), TYPE, CLASS, TTL, RDLENGTH e copia os rdlen bytes de RDATA
static bool
parse_rr(const vector<uint8_t>& b, size_t& off, DnsRR& rr)
{
  if (!decode_name(b, off, rr.name))
    return false;
  if (!read_u16(b, off, rr.type))
    return false;
  if (!read_u16(b, off, rr.rrclass))
    return false;
  if (!read_u32(b, off, rr.ttl))
    return false;

  uint16_t rdlen = 0;

  if (!read_u16(b, off, rdlen))
    return false;

  if (off + rdlen > b.size())
    return false;
  rr.rdata_offset = static_cast<uint32_t>(off); // onde o RDATA começa no wire
  rr.rdata.assign(b.begin() + off, b.begin() + off + rdlen);
  off += rdlen;
  return true;
}

// Lê o Header (6 campos de 16 bits). Garante pelo menos 12 bytes no começo.
bool
parseMessage(const vector<uint8_t>& data, DnsMessage& out)
{
  out = {}; // limpa
  out.wire = data; // guarda a mensagem bruta

  if (data.size() < 12)
    return false;
  
  size_t off = 0;

  if (!read_u16(data, off, out.header.id))
    return false;
  if (!read_u16(data, off, out.header.flags))
    return false;
  if (!read_u16(data, off, out.header.qdcount))
    return false;
  if (!read_u16(data, off, out.header.ancount)) 
    return false;
  if (!read_u16(data, off, out.header.nscount))
    return false;
  if (!read_u16(data, off, out.header.arcount))
    return false;

  // Questions
  out.questions.reserve(out.header.qdcount);
  for (uint16_t i = 0; i < out.header.qdcount; ++i)
  {
    DnsQuestion q;

    if (!parse_question(data, off, q))
      return false;
    out.questions.push_back(move(q));
  }

  // Answers
  out.answers.reserve(out.header.ancount);
  for (uint16_t i = 0; i < out.header.ancount; ++i)
  {
    DnsRR rr;

    if (!parse_rr(data, off, rr))
      return false;
    out.answers.push_back(move(rr));
  }

  // Authority
  out.authorities.reserve(out.header.nscount);
  for (uint16_t i = 0; i < out.header.nscount; ++i)
  {
    DnsRR rr;

    if (!parse_rr(data, off, rr))
      return false;
    out.authorities.push_back(move(rr));
  }

  // Additional
  out.additionals.reserve(out.header.arcount);
  for (uint16_t i = 0; i < out.header.arcount; ++i)
  {
    DnsRR rr;

    if (!parse_rr(data, off, rr))
      return false;
    out.additionals.push_back(move(rr));
  }

  // Conclui o parse. Se sobrarem bytes, simplesmente ignoramos (tolerante).
  return true;
}

string
toLowerName(const string& s)
{
  string r = s;

  transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  if (!r.empty() && r.back() == '.')
    r.pop_back();
  return r;
}

string
rdataToIPString(const DnsRR& rr)
{
  char buf[INET6_ADDRSTRLEN]{};

  if (rr.type == dnstype::A && rr.rdata.size() == 4)
  {
    // IPv4
    const uint8_t* p = rr.rdata.data();

    // formatação manual para portabilidade (sem depender de inet_ntop)
    return to_string(p[0]) + "." + to_string(p[1]) + "." +
           to_string(p[2]) + "." + to_string(p[3]);
  }
  if (rr.type == dnstype::AAAA && rr.rdata.size() == 16)
  {
    const void* src = rr.rdata.data();

#ifdef _WIN32
    // fallback simples (hex sem compressão ::) se inet_ntop não estiver disponível:
    const uint8_t* p = static_cast<const uint8_t*>(src);
    string out;

    for (int i = 0; i < 16; i += 2)
    {
      char chunk[5];

      snprintf(chunk, sizeof(chunk), "%02x%02x", p[i], p[i+1]);
      out += chunk;
      if (i < 14)
        out += ":";
    }
    return out;
#else
    if (::inet_ntop(AF_INET6, src, buf, sizeof(buf)))
      return string(buf);
    return "";
#endif
  }
  return "";
}

// Decodifica um domain name começando NO INÍCIO do RDATA (para NS/CNAME).
// Usa a mensagem original (msg.wire) e o offset rr.rdata_offset.
// IMPORTANTE: decode_name precisa do buffer inteiro por causa de compressão.
string rdataToDomainName(const DnsRR& rr, const DnsMessage& msg) {
  // Só faz sentido para NS e CNAME
  if (!(rr.type == dnstype::NS || rr.type == dnstype::CNAME))
    return "";
  if (rr.rdata.empty())
    return "";

  // Precisamos decodificar um NAME a partir do wire original,
  // iniciando exatamente no começo do RDATA desse RR.
  size_t off = static_cast<size_t>(rr.rdata_offset);
  string out;

  if (!decode_name(msg.wire, off, out))
    return "";
  return out;
}


// SOA: precisamos apenas do campo MINIMUM (último campo do SOA)
pair<bool, uint32_t>

rdataSOAMinimum(const DnsRR& rr, const DnsMessage& msg)
{
  if (rr.type != dnstype::SOA)
    return {false, 0};
  // SOA RDATA = MNAME (domain) | RNAME (domain) | SERIAL (u32) | REFRESH (u32)
  //             | RETRY (u32) | EXPIRE (u32) | MINIMUM (u32)
  
  size_t off = rr.rdata_offset;
  string tmp;

  // Precisamos decodificar dois domain names em sequência:
  // 1) MNAME
  if (!decode_name(msg.wire, off, tmp))
    return {false, 0};
  // 2) RNAME
  if (!decode_name(msg.wire, off, tmp))
    return {false, 0};

  // Agora vêm 5 campos u32:
  uint32_t serial, refresh, retry, expire, minimum;

  if (!read_u32(msg.wire, off, serial))
    return {false, 0};
  if (!read_u32(msg.wire, off, refresh))
    return {false, 0};
  if (!read_u32(msg.wire, off, retry))
    return {false, 0};
  if (!read_u32(msg.wire, off, expire))
    return {false, 0};
  if (!read_u32(msg.wire, off, minimum))
    return {false, 0};

  return {true, minimum};
}
