add_executable(ppltunnel-server server.cpp session.cpp main.cpp)
target_include_directories(ppltunnel-server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ppltunnel-server PRIVATE core dl ssl crypto)
target_link_options(ppltunnel-server PRIVATE -rdynamic)
