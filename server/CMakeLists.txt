add_executable(modtunnel-server server.cpp session.cpp main.cpp)
target_include_directories(modtunnel-server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(modtunnel-server PRIVATE core dl ssl crypto)
target_link_options(modtunnel-server PRIVATE -rdynamic)
