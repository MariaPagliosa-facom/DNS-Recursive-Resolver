# Resolvedor Recursivo DNS (com Cache e DoT)

Implementação de um **resolvedor recursivo DNS** do zero, usando **sockets básicos** (UDP/TCP) e **DNS over TLS (DoT)** no modo de 1 salto, com **cache positiva e negativa** local e via **daemon**.

## Funcionalidades
- Resolução **iterativa** (RD=0) com **delegações** (NS + glue).
- Suporte a **CNAME** encadeado.
- **Respostas negativas**: **NXDOMAIN** e **NODATA** com TTL negativo (SOA).
- **Fallback TCP** quando **TC=1** (truncamento no UDP).
- **Cache**:
  - **Positiva**: RRset + TTL mínimo;
  - **Negativa**: NXDOMAIN/NODATA + TTL (SOA.minimum);
  - **Local por processo** e via **daemon** externo (socket de texto).
- **DoT (DNS over TLS)** no **modo 1 salto** (recursivos públicos: 1.1.1.1, 8.8.8.8).
- Logs de **trace** com `--trace`.

> Não utilizamos bibliotecas “DNS prontas”. O wire format, sockets e a lógica de resolução foram implementados manualmente.

---

## Requisitos

- **Ubuntu/WSL2** (ou Linux equivalente)
- **CMake** e **g++ (C++17)**
- **OpenSSL** (para DoT)
- Pacotes:
  ```bash
  sudo apt-get update
  sudo apt-get install -y build-essential cmake libssl-dev ca-certificates
  sudo update-ca-certificates

## Compilação

    '''bash
    cmake -S . -B build
    cmake --build build -j

## Exemplos:
    '''bash
    # 1 salto (DNS “clássico”: UDP/TCP)
    ./build/tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A

    # 1 salto com DoT (TLS/853) — SNI obrigatório
    ./build/tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com
    ./build/tp1dns_cli --ns 8.8.8.8 --name example.com --qtype AAAA --mode dot --sni dns.google

    # (diagnóstico) ignorar validação de certificado no DoT:
    ./build/tp1dns_cli --ns 1.1.1.1 --name example.com --qtype A --mode dot --sni cloudflare-dns.com --insecure-dot

    # Resolução iterativa + cache (começando em root), com trace
    ./build/tp1dns_cli --ns 198.41.0.4 --name www.ufms.br --qtype A --iter --trace
    '''
> DoT é aplicado somente no modo 1 salto (recursivos). No modo iterativo, usamos UDP/TCP, pois autoritativos raramente oferecem DoT.
