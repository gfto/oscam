project (cscrypt)

file (GLOB cscrypt_srcs "*.c")
file (GLOB cscrypt_hdrs "*.h")

if (NOT HAVE_LIBCRYPTO)
    file (GLOB aes_srcs "aes/*.c")
    file (GLOB aes_hdrs "aes/*.h")
    file (GLOB sha_srcs "sha/*.c")
    file (GLOB sha_hdrs "sha/*.h")
endif (NOT HAVE_LIBCRYPTO)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_definitions ("-O2 -Winline -Werror -finline-functions -fomit-frame-pointer -s -m32")
  set (CMAKE_C_FLAGS_DEBUG "-O0 -g -m32")
  set (CMAKE_CXX_FLAGS_DEBUG "-O0 -g -m32")
else (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_definitions ("-Winline -Werror")
  set (CMAKE_C_FLAGS "-O2 -finline-functions -fomit-frame-pointer -s")
  set (CMAKE_C_FLAGS_DEBUG "-O0 -g")
  set (CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
endif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

set (lib_name "cscrypt")

add_library (${lib_name} STATIC ${cscrypt_srcs} ${aes_srcs} ${sha_srcs} ${cscrypt_hdrs} ${aes_hdrs} ${sha_hdrs})

