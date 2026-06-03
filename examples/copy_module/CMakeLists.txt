add_library(copy MODULE copy.c)
target_include_directories(copy PRIVATE ${CMAKE_SOURCE_DIR})
set_target_properties(copy PROPERTIES PREFIX "" SUFFIX ".so")

add_custom_command(TARGET copy POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:copy> ${CMAKE_SOURCE_DIR}/tests/test_modules/
  COMMENT "Copying copy.so to tests/test_modules/")
