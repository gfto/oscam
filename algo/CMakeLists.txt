project (algo)

file (GLOB algo_srcs "*.c")
file (GLOB algo_hdrs "*.h")

set (lib_name "algo")

add_library (${lib_name} STATIC ${algo_srcs} ${algo_hdrs})
