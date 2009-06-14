project (OSCam C)

cmake_minimum_required (VERSION 2.6)

#----------------------- detect system ------------------------------

if (CMAKE_CROSSCOMPILING)
    if (OSCAM_SYSTEM_NAME MATCHES "Tuxbox")
        set (OSCamOperatingSystem "Tuxbox")
    elseif (OSCAM_SYSTEM_NAME MATCHES "Fonera2")
        set (OSCamOperatingSystem "Fonera2")
    else (OSCAM_SYSTEM_NAME MATCHES "Tuxbox")
        set (OSCamOperatingSystem "Unknown")
    endif (OSCAM_SYSTEM_NAME MATCHES "Tuxbox")
else (CMAKE_CROSSCOMPILING)
    if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        set (OSCamOperatingSystem "Linux")
    elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        set (OSCamOperatingSystem "Mac OS X")
    else (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        set (OSCamOperatingSystem "Unknown")
    endif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
endif (CMAKE_CROSSCOMPILING)

#----------------------- some paths ------------------------------

set (OPTIONAL_LINK_DIR "" CACHE STRING "Some optional link directories")
set (OPTIONAL_INCLUDE_DIR "" CACHE STRING "Some optional include directories")

include_directories (
    ${CMAKE_CURRENT_SOURCE_DIR}/csctapi
    ${CMAKE_CURRENT_SOURCE_DIR}/cscrypt
    ${OPTIONAL_INCLUDE_DIR}
    )
link_directories (${OPTIONAL_LINK_DIR})

#----------------------- global options ------------------------------

if (OSCamOperatingSystem MATCHES "Linux")
    add_definitions ("-DOS_LINUX")
elseif (OSCamOperatingSystem MATCHES "Mac OS X")
    add_definitions ("-DOS_MACOSX -DNEED_DAEMON -DCS_NOSHM -DHAVE_PTHREAD_H -DUSE_PTHREAD")
elseif (OSCamOperatingSystem MATCHES "Tuxbox")
    add_definitions ("-DOS_LINUX -DTUXBOX -DPPC")
elseif (OSCamOperatingSystem MATCHES "Fonera2")
    add_definitions ("-DOS_LINUX -DMIPSEL -DUCLIBC")
endif (OSCamOperatingSystem MATCHES "Linux")

#----------------------- subdirectories ------------------------------

add_subdirectory (csctapi)
add_subdirectory (cscrypt)

#----------------------- file groups ------------------------------

file (GLOB csmodules_srcs "module-*.c")
file (GLOB csmodules_hdrs "module-*.h")
file (GLOB csreaders_srcs "reader-*.c")
file (GLOB csreaders_hdrs "reader-*.h")
file (GLOB csoscam_srcs "oscam-*.c")
file (GLOB csoscam_hdrs "oscam-*.h")
file (GLOB exe_srcs "oscam.c")
file (GLOB exe_hdrs "globals.h")
file (GLOB all_srcs ${csmodules_srcs} ${csreaders_srcs} ${csoscam_srcs} ${exe_srcs})

#----------------------- modules ------------------------------

set (csmodules "csmodules")
add_library (${csmodules} STATIC ${csmodules_srcs} ${csmodules_hdrs})

#----------------------- readers ------------------------------

set (csreaders "csreaders")
add_library (${csreaders} STATIC ${csreaders_srcs} ${csreaders_hdrs})

#----------------------- other oscam files ------------------------------

set (csoscam "csoscam")
add_library (${csoscam} STATIC ${csoscam_srcs} ${csoscam_hdrs})

#----------------------- the executable ------------------------------

set (exe_name "oscam")
add_executable (${exe_name} ${exe_srcs} ${exe_hdrs})
target_link_libraries (${exe_name} crypto pthread ${csoscam} ${csmodules} ${csreaders} csctapi cscrypt)
add_dependencies (${exe_name} ${csoscam} ${csreaders} ${csmodules})

#----------------------- specific options ------------------------------

if (OSCamOperatingSystem MATCHES "Linux")
elseif (OSCamOperatingSystem MATCHES "Mac OS X")
elseif (OSCamOperatingSystem MATCHES "Tuxbox")
    target_link_libraries ( ${exe_name} dl)
elseif (OSCamOperatingSystem MATCHES "Fonera2")
endif (OSCamOperatingSystem MATCHES "Linux")

set_source_files_properties (${all_srcs} PROPERTIES COMPILE_FLAGS "-O3 -Winline -Werror -finline-functions -fomit-frame-pointer")

#----------------------- printout resume -----------------------------

message (STATUS "")
message (STATUS "  operating system: ${OSCamOperatingSystem}")
message (STATUS "")
