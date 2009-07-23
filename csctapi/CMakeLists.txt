project (csctapi)

file (GLOB csctapi_srcs "*.c")
file (GLOB csctapi_hdrs "*.h")

add_definitions ("-O3 -Winline -Werror -finline-functions -fomit-frame-pointer -s")

set (lib_name "csctapi")

add_library (${lib_name} STATIC ${csctapi_srcs} ${csctapi_hdrs})

