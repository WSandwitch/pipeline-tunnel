cmake_minimum_required(VERSION 3.20)
project(modtunnel C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
add_subdirectory(common)
add_subdirectory(core)
add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(modules)

option(BUILD_MODULE_TESTER "Build module_tester" OFF)
if(BUILD_MODULE_TESTER)
    add_subdirectory(module_tester)
endif()

# pack target: copy binaries and .so to out/
set(PACK_DIR "${CMAKE_SOURCE_DIR}/out")
add_custom_target(pack
  COMMAND ${CMAKE_COMMAND} -E make_directory ${PACK_DIR}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${PACK_DIR}/modules
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:modtunnel-server> ${PACK_DIR}/
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:modtunnel-client> ${PACK_DIR}/
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:copy> ${PACK_DIR}/modules/
  COMMENT "Packing binaries and modules to ${PACK_DIR}"
  DEPENDS modtunnel-server modtunnel-client copy
)
