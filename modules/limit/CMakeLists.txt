set(LIMIT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/limit.zig)
set(LIMIT_OUT ${CMAKE_CURRENT_BINARY_DIR}/limit.so)

find_program(ZIG_COMPILER zig
  PATHS /tmp/zig-x86_64-linux-0.16.0
  NO_DEFAULT_PATH)
if(NOT ZIG_COMPILER)
  find_program(ZIG_COMPILER zig)
endif()

add_custom_command(OUTPUT ${LIMIT_OUT}
  COMMAND ${ZIG_COMPILER} build-lib -dynamic -O ReleaseFast --global-cache-dir ${CMAKE_CURRENT_BINARY_DIR}/.zig-cache ${LIMIT_SRC} -femit-bin=${LIMIT_OUT}
  DEPENDS ${LIMIT_SRC}
  COMMENT "Building limit.so (Zig)")

add_custom_target(limit ALL DEPENDS ${LIMIT_OUT})

set_target_properties(limit PROPERTIES
  LIMIT_SO_PATH "${LIMIT_OUT}")

add_custom_command(TARGET limit POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy ${LIMIT_OUT} ${CMAKE_BINARY_DIR}/tests/test_modules/
  COMMAND ${CMAKE_COMMAND} -E copy ${LIMIT_OUT} ${CMAKE_BINARY_DIR}/modules/
  COMMENT "Copying limit.so to tests/test_modules/ and modules/")
