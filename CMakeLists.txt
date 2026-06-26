cmake_minimum_required(VERSION 3.20)
project(modtunnel C CXX)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(TRACE_ON "Enable TRACE/debug prints (off by default)" OFF)
if(TRACE_ON)
    add_definitions(-DTRACE_ON)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
add_subdirectory(common)
add_subdirectory(core)
add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(modules)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/tests/test_modules)

option(BUILD_MODULE_TESTER "Build module_tester" ON)
if(BUILD_MODULE_TESTER)
    add_subdirectory(module_tester)
endif()

# pack target: copy binaries and .so to out/
set(PACK_DIR "${CMAKE_SOURCE_DIR}/out")
# Alpine's musl Rust target does not support cdylib crate type
if(EXISTS "/etc/alpine-release")
  set(MODULES base64 split limit compress)
  add_custom_target(pack
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PACK_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PACK_DIR}/modules
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:base64> ${PACK_DIR}/modules/
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:split> ${PACK_DIR}/modules/
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/modules/limit/limit.so ${PACK_DIR}/modules/
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/modules/compress/compress.so ${PACK_DIR}/modules/
    COMMENT "Packing binaries and modules to ${PACK_DIR}"
    DEPENDS ppltunnel-server ppltunnel-client ${MODULES}
  )
else()
  set(MODULES base64 split limit compress crypto)
  add_custom_target(pack
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PACK_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PACK_DIR}/modules
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:base64> ${PACK_DIR}/modules/
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:split> ${PACK_DIR}/modules/
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/modules/limit/limit.so ${PACK_DIR}/modules/
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/modules/compress/compress.so ${PACK_DIR}/modules/
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/modules/crypto/release/libcrypto.so ${PACK_DIR}/modules/
    COMMENT "Packing binaries and modules to ${PACK_DIR}"
    DEPENDS ppltunnel-server ppltunnel-client ${MODULES}
  )
endif()
