project (cscrypt)

file (GLOB cscrypt_srcs "*.c")
file (GLOB cscrypt_hdrs "*.h")

set (lib_name "cscrypt")

add_library (${lib_name} STATIC ${cscrypt_srcs} ${cscrypt_hdrs})

