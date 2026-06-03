add_library(compress MODULE compress.c)
target_include_directories(compress PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(compress PRIVATE z zstd)
set_target_properties(compress PROPERTIES PREFIX "" SUFFIX ".so")

add_custom_command(TARGET compress POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:compress> ${CMAKE_SOURCE_DIR}/test_modules/
  COMMENT "Copying compress.so to test_modules/")