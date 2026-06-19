cmake_minimum_required(VERSION 3.20)
project(modtunnel C CXX)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG)
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

option(BUILD_MODULE_TESTER "Build module_tester" OFF)
if(BUILD_MODULE_TESTER)
    add_subdirectory(module_tester)
endif()

# pack target: copy binaries and .so to out/
set(PACK_DIR "${CMAKE_SOURCE_DIR}/out")
set(MODULES copy base64 split)
add_custom_target(pack
  COMMAND ${CMAKE_COMMAND} -E make_directory ${PACK_DIR}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${PACK_DIR}/modules
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ppltunnel-server> ${PACK_DIR}/
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ppltunnel-client> ${PACK_DIR}/
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:copy> ${PACK_DIR}/modules/
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:base64> ${PACK_DIR}/modules/
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:split> ${PACK_DIR}/modules/
  COMMENT "Packing binaries and modules to ${PACK_DIR}"
  DEPENDS ppltunnel-server ppltunnel-client ${MODULES}
)
