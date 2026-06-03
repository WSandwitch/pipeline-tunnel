add_library(sleep MODULE sleep.c)
target_include_directories(sleep PRIVATE ${CMAKE_SOURCE_DIR})
set_target_properties(sleep PROPERTIES PREFIX "" SUFFIX ".so")

add_custom_command(TARGET sleep POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:sleep> ${CMAKE_SOURCE_DIR}/tests/test_modules/
  COMMENT "Copying sleep.so to tests/test_modules/")
