project (cscrypt)

file (GLOB cscrypt_srcs "*.c")
file (GLOB cscrypt_hdrs "*.h")

if (NOT HAVE_AES)
    file (GLOB aes_srcs "aes/*.c")
    file (GLOB aes_hdrs "aes/*.h")
endif (NOT HAVE_AES)

if (NOT HAVE_SHA)
    file (GLOB sha_srcs "sha/*.c")
    file (GLOB sha_hdrs "sha/*.h")
endif (NOT HAVE_SHA)

add_definitions ("-O3 -Winline -finline-functions -fomit-frame-pointer -s")

set (lib_name "cscrypt")

add_library (${lib_name} STATIC ${cscrypt_srcs} ${aes_srcs} ${sha_srcs} ${cscrypt_hdrs} ${aes_hdrs} ${sha_hdrs})

