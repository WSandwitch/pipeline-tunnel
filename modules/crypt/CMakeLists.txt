add_library(crypt MODULE crypt.c)
target_include_directories(crypt PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(crypt PRIVATE OpenSSL::Crypto)
set_target_properties(crypt PROPERTIES PREFIX "" SUFFIX ".so")

add_custom_command(TARGET crypt POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:crypt> ${CMAKE_BINARY_DIR}/tests/test_modules/
  COMMENT "Copying crypt.so to tests/test_modules/")