add_library(limit MODULE limit.c)
target_include_directories(limit PRIVATE ${CMAKE_SOURCE_DIR})
set_target_properties(limit PROPERTIES PREFIX "" SUFFIX ".so")

add_custom_command(TARGET limit POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:limit> ${CMAKE_BINARY_DIR}/tests/test_modules/
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:limit> ${CMAKE_BINARY_DIR}/modules/
  COMMENT "Copying limit.so to tests/test_modules/ and modules/")
