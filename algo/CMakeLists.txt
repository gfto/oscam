project (algo)

file (GLOB algo_srcs "*.c")
file (GLOB algo_hdrs "*.h")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_definitions ("-O2 -Winline -Werror -finline-functions -fomit-frame-pointer -s -m32")
  set (CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")
  set (CMAKE_CXX_FLAGS_DEBUG "-O0 -ggdb")
else (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_definitions ("-Winline -Werror")
  set (CMAKE_C_FLAGS "-O2 -finline-functions -fomit-frame-pointer -s")
  set (CMAKE_C_FLAGS_DEBUG "-O0 -g")
  set (CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
endif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

set (lib_name "algo")

add_library (${lib_name} STATIC ${algo_srcs} ${algo_hdrs})
