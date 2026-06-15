set(AKLOMP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/aklomp-base64)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64|x86|i386)")
    set(BASE64_WITH_SSSE3 1)
    set(BASE64_WITH_SSE41 1)
    set(BASE64_WITH_SSE42 1)
    set(BASE64_WITH_AVX 1)
    set(BASE64_WITH_AVX2 1)
    set(BASE64_WITH_AVX512 1)
    set(BASE64_WITH_NEON32 0)
    set(BASE64_WITH_NEON64 0)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "(aarch64|ARM64)")
    set(BASE64_WITH_SSSE3 0)
    set(BASE64_WITH_SSE41 0)
    set(BASE64_WITH_SSE42 0)
    set(BASE64_WITH_AVX 0)
    set(BASE64_WITH_AVX2 0)
    set(BASE64_WITH_AVX512 0)
    set(BASE64_WITH_NEON32 0)
    set(BASE64_WITH_NEON64 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "(arm|ARM)")
    set(BASE64_WITH_SSSE3 0)
    set(BASE64_WITH_SSE41 0)
    set(BASE64_WITH_SSE42 0)
    set(BASE64_WITH_AVX 0)
    set(BASE64_WITH_AVX2 0)
    set(BASE64_WITH_AVX512 0)
    set(BASE64_WITH_NEON32 1)
    set(BASE64_WITH_NEON64 0)
else()
    set(BASE64_WITH_SSSE3 0)
    set(BASE64_WITH_SSE41 0)
    set(BASE64_WITH_SSE42 0)
    set(BASE64_WITH_AVX 0)
    set(BASE64_WITH_AVX2 0)
    set(BASE64_WITH_AVX512 0)
    set(BASE64_WITH_NEON32 0)
    set(BASE64_WITH_NEON64 0)
endif()

configure_file(
    ${AKLOMP_DIR}/cmake/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/aklomp-base64/config.h
    @ONLY
)

add_library(base64 MODULE
    base64.c
    ${AKLOMP_DIR}/lib/lib.c
    ${AKLOMP_DIR}/lib/codec_choose.c
    ${AKLOMP_DIR}/lib/tables/tables.c
    ${AKLOMP_DIR}/lib/arch/generic/codec.c
)

target_include_directories(base64 PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${AKLOMP_DIR}/include
    ${AKLOMP_DIR}/lib
    ${CMAKE_CURRENT_BINARY_DIR}/aklomp-base64
)

target_compile_definitions(base64 PRIVATE BASE64_STATIC_DEFINE)

if(BASE64_WITH_SSSE3)
    target_sources(base64 PRIVATE ${AKLOMP_DIR}/lib/arch/ssse3/codec.c)
    set_source_files_properties(${AKLOMP_DIR}/lib/arch/ssse3/codec.c PROPERTIES
        COMPILE_FLAGS "-mssse3")
endif()
if(BASE64_WITH_SSE41)
    target_sources(base64 PRIVATE ${AKLOMP_DIR}/lib/arch/sse41/codec.c)
    set_source_files_properties(${AKLOMP_DIR}/lib/arch/sse41/codec.c PROPERTIES
        COMPILE_FLAGS "-msse4.1")
endif()
if(BASE64_WITH_SSE42)
    target_sources(base64 PRIVATE ${AKLOMP_DIR}/lib/arch/sse42/codec.c)
    set_source_files_properties(${AKLOMP_DIR}/lib/arch/sse42/codec.c PROPERTIES
        COMPILE_FLAGS "-msse4.2")
endif()
if(BASE64_WITH_AVX)
    target_sources(base64 PRIVATE ${AKLOMP_DIR}/lib/arch/avx/codec.c)
    set_source_files_properties(${AKLOMP_DIR}/lib/arch/avx/codec.c PROPERTIES
        COMPILE_FLAGS "-mavx")
endif()
if(BASE64_WITH_AVX2)
    target_sources(base64 PRIVATE ${AKLOMP_DIR}/lib/arch/avx2/codec.c)
    set_source_files_properties(${AKLOMP_DIR}/lib/arch/avx2/codec.c PROPERTIES
        COMPILE_FLAGS "-mavx2")
endif()
if(BASE64_WITH_AVX512)
    target_sources(base64 PRIVATE ${AKLOMP_DIR}/lib/arch/avx512/codec.c)
    set_source_files_properties(${AKLOMP_DIR}/lib/arch/avx512/codec.c PROPERTIES
        COMPILE_FLAGS "-mavx512vl -mavx512vbmi")
endif()
target_sources(base64 PRIVATE ${AKLOMP_DIR}/lib/arch/neon32/codec.c)
target_sources(base64 PRIVATE ${AKLOMP_DIR}/lib/arch/neon64/codec.c)

set_target_properties(base64 PROPERTIES PREFIX "" SUFFIX ".so")

add_custom_command(TARGET base64 POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:base64> ${CMAKE_BINARY_DIR}/tests/test_modules/
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:base64> ${CMAKE_BINARY_DIR}/modules/
  COMMENT "Copying base64.so to tests/test_modules/ and modules/")
