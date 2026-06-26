set(CRYPTO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CRYPTO_OUT ${CMAKE_CURRENT_BINARY_DIR}/release/libcrypto.so)

find_program(CARGO cargo
  PATHS /usr/local/bin /usr/local/lib/rust/cargo/bin /root/.cargo/bin $ENV{HOME}/.cargo/bin)

add_custom_command(OUTPUT ${CRYPTO_OUT}
  COMMAND ${CARGO} build --release --manifest-path ${CRYPTO_SRC_DIR}/Cargo.toml
    --target-dir ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${CRYPTO_SRC_DIR}/Cargo.toml ${CRYPTO_SRC_DIR}/src/lib.rs
  COMMENT "Building crypto.so (Rust)")

add_custom_target(crypto ALL DEPENDS ${CRYPTO_OUT})

add_custom_command(TARGET crypto POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy ${CRYPTO_OUT} ${CMAKE_BINARY_DIR}/tests/test_modules/
  COMMAND ${CMAKE_COMMAND} -E copy ${CRYPTO_OUT} ${CMAKE_BINARY_DIR}/modules/
  COMMENT "Copying crypto.so to tests/test_modules/ and modules/")
