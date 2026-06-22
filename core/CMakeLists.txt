add_library(core STATIC
    config.cpp
    protocol.cpp
    module_base.cpp
    chain.cpp
    kernel.cpp
    thread_pool.cpp
    modules/modules.cpp
    modules/copy.cpp
)
target_include_directories(core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(core PUBLIC common)
target_link_libraries(core PUBLIC ${CMAKE_DL_LIBS})
