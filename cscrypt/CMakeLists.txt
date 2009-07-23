project (cscrypt)

file (GLOB cscrypt_srcs "*.c")
file (GLOB cscrypt_hdrs "*.h")

if (NOT HAVE_AES)
    file (GLOB aes_srcs "aes/*.c")
    file (GLOB aes_hdrs "aes/*.h")
endif (NOT HAVE_AES)

add_definitions ("-O3 -Winline -Werror -finline-functions -fomit-frame-pointer -s")

set (lib_name "cscrypt")

add_library (${lib_name} STATIC ${cscrypt_srcs} ${aes_srcs} ${cscrypt_hdrs} ${aes_hdrs})

