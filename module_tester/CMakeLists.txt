add_executable(ppltunnel-tester main.cpp)
target_include_directories(ppltunnel-tester PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(ppltunnel-tester PRIVATE core dl OpenSSL::SSL OpenSSL::Crypto)
