add_library(base64 MODULE base64.c)
target_include_directories(base64 PRIVATE ${CMAKE_SOURCE_DIR})
set_target_properties(base64 PROPERTIES PREFIX "" SUFFIX ".so")

add_custom_command(TARGET base64 POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:base64> ${CMAKE_SOURCE_DIR}/tests/test_modules/
  COMMENT "Copying base64.so to tests/test_modules/")
