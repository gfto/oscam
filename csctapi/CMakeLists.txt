project (csctapi)

file (GLOB csctapi_srcs "*.c")
file (GLOB csctapi_hdrs "*.h")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
add_definitions ("-O2 -Winline -Werror -finline-functions -fomit-frame-pointer -s -m32")
else (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
add_definitions ("-O2 -Winline -Werror -finline-functions -fomit-frame-pointer -s")
endif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

set (lib_name "csctapi")

add_library (${lib_name} STATIC ${csctapi_srcs} ${csctapi_hdrs})

