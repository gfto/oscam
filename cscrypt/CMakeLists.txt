project (cscrypt)

file (GLOB cscrypt_srcs "*.c")
file (GLOB cscrypt_hdrs "*.h")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_definitions ("-s -m32")
  set (CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")
  set (CMAKE_CXX_FLAGS_DEBUG "-O0 -ggdb")
else (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set (CMAKE_C_FLAGS "-O2 -s")
  set (CMAKE_C_FLAGS_DEBUG "-O0 -g")
  set (CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
endif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

set (lib_name "cscrypt")

add_library (${lib_name} STATIC ${cscrypt_srcs} ${cscrypt_hdrs})

