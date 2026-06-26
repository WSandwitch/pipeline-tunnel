# copy is builtin — see core/modules/copy.cpp
add_subdirectory(base64)
add_subdirectory(split)
add_subdirectory(limit)
add_subdirectory(compress)
# Alpine musl Rust target does not support cdylib crate type
if(NOT EXISTS "/etc/alpine-release")
  add_subdirectory(crypto)
endif()