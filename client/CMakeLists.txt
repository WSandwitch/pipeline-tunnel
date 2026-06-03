add_executable(modtunnel-client client.cpp listener.cpp main.cpp)
target_include_directories(modtunnel-client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(modtunnel-client PRIVATE core dl ssl crypto)
