add_executable(ppltunnel-client client.cpp main.cpp)
target_include_directories(ppltunnel-client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ppltunnel-client PRIVATE core dl ssl crypto)
