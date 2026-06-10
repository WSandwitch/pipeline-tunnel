add_library(split MODULE split.cpp)
target_include_directories(split PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(split PRIVATE stdc++)
set_target_properties(split PROPERTIES PREFIX "" SUFFIX ".so")

add_custom_command(TARGET split POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:split> ${CMAKE_BINARY_DIR}/tests/test_modules/
  COMMENT "Copying split.so to tests/test_modules/")
