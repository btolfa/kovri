cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(kovri-tests CXX)

add_executable(kovri-tests 
  client/address_book/impl.cc
  client/api/i2p_control/data.cc
  client/api/i2p_control/parser.cc
  client/reseed.cc
  client/proxy/http.cc
  client/util/http.cc
  client/util/parse.cc
  client/util/zip.cc
  core/crypto/aes.cc
  core/crypto/dsa.cc
  core/crypto/eddsa25519.cc
  core/crypto/elgamal.cc
  core/crypto/radix.cc
  core/crypto/rand.cc
  core/crypto/util/x509.cc
  core/router/identity.cc
  core/router/transports/ssu/packet.cc
  core/util/byte_stream.cc
  main.cc
  core/router/identity.h)

set_property(SOURCE main.cc PROPERTY COTIRE_EXCLUDED TRUE)

find_package(Boost REQUIRED COMPONENTS unit_test_framework)

target_link_libraries(kovri-tests PRIVATE 
  Boost::unit_test_framework
  kovri-private
  kovri-client)

if (COMMAND cotire)
  set_target_properties(kovri-tests PROPERTIES COTIRE_PREFIX_HEADER_INCLUDE_PATH "${CMAKE_SOURCE_DIR}/deps")
  cotire(kovri-tests)
endif()

install(TARGETS kovri-tests RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}) 

add_test(NAME KovriTest COMMAND kovri-tests)
