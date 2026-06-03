add_library(split MODULE split.c)
target_include_directories(split PRIVATE ${CMAKE_SOURCE_DIR})
set_target_properties(split PROPERTIES PREFIX "" SUFFIX ".so")

add_custom_command(TARGET split POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:split> ${CMAKE_SOURCE_DIR}/tests/test_modules/
  COMMENT "Copying split.so to tests/test_modules/")