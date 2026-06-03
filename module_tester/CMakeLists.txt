add_executable(modtunnel-tester main.cpp)
target_include_directories(modtunnel-tester PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(modtunnel-tester PRIVATE core dl)