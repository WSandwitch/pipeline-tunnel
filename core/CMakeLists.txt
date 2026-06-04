add_library(core STATIC
    config.cpp
    protocol.cpp
    module.cpp
    kernel.cpp
)
target_include_directories(core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(core PUBLIC common)
