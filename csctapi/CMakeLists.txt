project (csctapi)

file (GLOB csctapi_srcs "*.c")
file (GLOB csctapi_hdrs "*.h")

set (lib_name "csctapi")

add_library (${lib_name} STATIC ${csctapi_srcs} ${csctapi_hdrs})

