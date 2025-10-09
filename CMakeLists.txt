cmake_minimum_required(VERSION 3.16)
project(tp1dns CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ===== Qualidade / flags =====
if (MSVC)
  add_compile_options(/W4 /permissive-)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Otimização padrão para Release
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ===== Dependências =====
find_package(OpenSSL REQUIRED)

# ===== Biblioteca comum =====
add_library(tp1dns STATIC
  src/dns_wire.cpp
  src/transport.cpp
  src/transport_tls.cpp
  src/cache.cpp
  src/resolver.cpp
  src/cache_client.cpp
)

# Headers públicos (src/) pra quem linkar com tp1dns
target_include_directories(tp1dns PUBLIC ${CMAKE_SOURCE_DIR}/src)

# Propaga OpenSSL para quem linkar com tp1dns
target_link_libraries(tp1dns PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# Winsock no Windows (propaga também)
if (WIN32)
  target_link_libraries(tp1dns PUBLIC Ws2_32)
endif()

# ===== Executável do CLI =====
add_executable(tp1dns_cli
  src/main.cpp
)
target_link_libraries(tp1dns_cli PRIVATE tp1dns)

# ===== Executável do daemon de cache =====
# Em vez de recompilar fontes, só linkamos contra a lib (reutiliza cache/dns_wire/etc)
add_executable(cache_daemon
  src/cache_daemon_main.cpp
)
target_link_libraries(cache_daemon PRIVATE tp1dns)

# ===== Utilitário de inspeção do cache =====
add_executable(cachectl
  src/cachectl.cpp
)
# Ele usa sockets também (no Windows), então já recebe Ws2_32 via tp1dns (propagado).
target_link_libraries(cachectl PRIVATE tp1dns)
