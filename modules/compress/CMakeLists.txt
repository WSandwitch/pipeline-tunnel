set(COMPRESS_SRC ${CMAKE_CURRENT_SOURCE_DIR}/compress.nim)
set(COMPRESS_OUT ${CMAKE_CURRENT_BINARY_DIR}/compress.so)

find_program(NIM_COMPILER nim
  PATHS /tmp/nim/nim-2.2.2/bin /usr/local/nim-2.2.2/bin
  NO_DEFAULT_PATH)
if(NOT NIM_COMPILER)
  find_program(NIM_COMPILER nim)
endif()

add_custom_command(OUTPUT ${COMPRESS_OUT}
  COMMAND ${NIM_COMPILER} c --app:lib --mm:none --opt:speed -d:release
    --nimcache:/tmp/nimcache --out:${COMPRESS_OUT} ${COMPRESS_SRC}
  DEPENDS ${COMPRESS_SRC}
    ${CMAKE_CURRENT_SOURCE_DIR}/helpers.nim
    ${CMAKE_CURRENT_SOURCE_DIR}/rle_impl.nim
  COMMENT "Building compress.so (Nim)")

add_custom_target(compress ALL DEPENDS ${COMPRESS_OUT})

set_target_properties(compress PROPERTIES
  COMPRESS_SO_PATH "${COMPRESS_OUT}")

add_custom_command(TARGET compress POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy ${COMPRESS_OUT} ${CMAKE_BINARY_DIR}/tests/test_modules/
  COMMAND ${CMAKE_COMMAND} -E copy ${COMPRESS_OUT} ${CMAKE_BINARY_DIR}/modules/
  COMMENT "Copying compress.so to tests/test_modules/ and modules/")
