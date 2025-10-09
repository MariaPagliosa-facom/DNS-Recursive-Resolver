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

## Copmilação

    '''bash
    cmake -S . -B build
    cmake --build build -j

