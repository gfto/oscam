project (OSCam C)

#----------------------- minimum version of cmake to use ------------

# if you want to switch to 2.6 min, please look at the escaped definitions
# later in this file (the add_definitions in 2.6 don't need to be escaped),
# and remove the CMP0005 policy.
# the CMP0003 could also be removed for cmake 2.6
cmake_minimum_required (VERSION 2.4)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0005 OLD)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

#----------------------- detect system ------------------------------

if (CMAKE_CROSSCOMPILING)
    if (OSCAM_SYSTEM_NAME MATCHES "Tuxbox")
        set (OSCamOperatingSystem "Tuxbox")
        set (CS_OS_HW "tuxbox")
        set (CS_OS_SYS "linux")
    elseif (OSCAM_SYSTEM_NAME MATCHES "TripleDragon")
        set (OSCamOperatingSystem "TripleDragon")
        set (CS_OS_HW "tuxbox")
        set (CS_OS_SYS "linux")
    elseif (OSCAM_SYSTEM_NAME MATCHES "Coolstream")
        set (OSCamOperatingSystem "NeutrinoHD")
        set (CS_OS_HW "coolstream")
        set (CS_OS_SYS "linux")
    elseif (OSCAM_SYSTEM_NAME MATCHES "NSLU2")
        set (OSCamOperatingSystem "SlugOS")
        set (CS_OS_HW "nslu2")
        set (CS_OS_SYS "linux")
    elseif (OSCAM_SYSTEM_NAME MATCHES "Dockstar")
        set (OSCamOperatingSystem "OpenWRT")
        set (CS_OS_HW "dockstar")
        set (CS_OS_SYS "linux")
    elseif (OSCAM_SYSTEM_NAME MATCHES "Fonera2")
        set (OSCamOperatingSystem "Fonera2")
        set (CS_OS_HW "fonera2")
        set (CS_OS_SYS "linux")
    elseif (OSCAM_SYSTEM_NAME MATCHES "DIR-825")
        set (OSCamOperatingSystem "DIR-825")
        set (CS_OS_HW "dir825")
        set (CS_OS_SYS "linux")
    elseif (OSCAM_SYSTEM_NAME MATCHES "AZBox")
        set (OSCamOperatingSystem "AZBox")
        set (CS_OS_HW "azbox")
        set (CS_OS_SYS "linux")
    elseif (OSCAM_SYSTEM_NAME MATCHES "agv2+w")
        set (OSCamOperatingSystem "agv2+w")
        set (CS_OS_HW "agv2+w")
        set (CS_OS_SYS "linux")
    elseif (OSCAM_SYSTEM_NAME MATCHES "WRT54G")
        set (OSCamOperatingSystem "WRT54G")
        set (CS_OS_HW "wrt54g")
        set (CS_OS_SYS "linux")
    elseif (OSCAM_SYSTEM_NAME MATCHES "Amino")
        set (OSCamOperatingSystem "Amino")
        set (CS_OS_HW "amino")
        set (CS_OS_SYS "linux")
    elseif (OSCAM_SYSTEM_NAME MATCHES "QboxHD")
        set (OSCamOperatingSystem "QboxHD")
        set (CS_OS_HW "qboxhd")
        set (CS_OS_SYS "linux")
    else (OSCAM_SYSTEM_NAME MATCHES "Tuxbox")
        message (STATUS "Unknown cross system name: <${CMAKE_SYSTEM_NAME}>")
        set (OSCamOperatingSystem "Unknown")
        set (CS_OS_HW "unknown")
        set (CS_OS_SYS "unknown")
    endif (OSCAM_SYSTEM_NAME MATCHES "Tuxbox")
else (CMAKE_CROSSCOMPILING)
    if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        set (OSCamOperatingSystem "Linux")
        set (CS_OS_HW "pc")
        set (CS_OS_SYS "linux")
    elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
        set (OSCamOperatingSystem "FreeBSD")
        set (CS_OS_HW "pc")
        set (CS_OS_SYS "freebsd")
    elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        set (OSCamOperatingSystem "Mac OS X")
        set (CS_OS_HW "mac")
        set (CS_OS_SYS "macosx")
        SET( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32" )
        SET( CMAKE_CFLAGS "${CMAKE_CFLAGS} -m32" )
    elseif (${CYGWIN})
        set (OSCamOperatingSystem "Windows/Cygwin")
        set (CS_OS_HW "pc")
        set (CS_OS_SYS "cygwin")
        set (CMAKE_SYSTEM_PROCESSOR "i386")
    else (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        message (STATUS "Unknown system name: <${CMAKE_SYSTEM_NAME}>")
        set (OSCamOperatingSystem "Unknown")
        set (CS_OS_HW "unknown")
        set (CS_OS_SYS "unknown")
    endif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
endif (CMAKE_CROSSCOMPILING)

#----------------------- some paths ------------------------------

set (OPTIONAL_LINK_DIR "" CACHE STRING "Some optional link directories")
set (OPTIONAL_INCLUDE_DIR "" CACHE STRING "Some optional include directories")

if (OSCamOperatingSystem MATCHES "Windows/Cygwin")
if(CS_WITH_GBOX)
    include_directories (
        ${CMAKE_CURRENT_SOURCE_DIR}/csctapi
        ${CMAKE_CURRENT_SOURCE_DIR}/cscrypt
        ${CMAKE_CURRENT_SOURCE_DIR}/csgbox
        ${CMAKE_CURRENT_SOURCE_DIR}/cygwin
        /usr/include/w32api
        ${OPTIONAL_INCLUDE_DIR}
    )
else(CS_WITH_GBOX)
    include_directories (
        ${CMAKE_CURRENT_SOURCE_DIR}/csctapi
        ${CMAKE_CURRENT_SOURCE_DIR}/cscrypt
        ${CMAKE_CURRENT_SOURCE_DIR}/csgbox
        ${CMAKE_CURRENT_SOURCE_DIR}/cygwin
        /usr/include/w32api
        ${OPTIONAL_INCLUDE_DIR}
    )
endif(CS_WITH_GBOX)
else (OSCamOperatingSystem MATCHES "Windows/Cygwin")
if(CS_WITH_GBOX)
    include_directories (
        ${CMAKE_CURRENT_SOURCE_DIR}/csctapi
        ${CMAKE_CURRENT_SOURCE_DIR}/cscrypt
        ${CMAKE_CURRENT_SOURCE_DIR}/csgbox
        ${OPTIONAL_INCLUDE_DIR}
        )
else(CS_WITH_GBOX)
    include_directories (
        ${CMAKE_CURRENT_SOURCE_DIR}/csctapi
        ${CMAKE_CURRENT_SOURCE_DIR}/cscrypt
        ${OPTIONAL_INCLUDE_DIR}
        )
endif(CS_WITH_GBOX)
endif (OSCamOperatingSystem MATCHES "Windows/Cygwin")

if(OSCamOperatingSystem MATCHES "Windows/Cygwin")
link_directories (
    /usr/lib
    /usr/lib/w32api
    /cygdrive/c/WINDOWS/system32/
    ${OPTIONAL_LINK_DIR}
    )
else (OSCamOperatingSystem MATCHES "Windows/Cygwin")
link_directories (
    ${OPTIONAL_LINK_DIR}
    )
endif (OSCamOperatingSystem MATCHES "Windows/Cygwin")

#----------------------- global options ------------------------------

if (OSCamOperatingSystem MATCHES "Linux")
    add_definitions ("-DOS_LINUX")
    set (DEFAULT_CS_CONFDIR "/usr/local/etc")
elseif (OSCamOperatingSystem MATCHES "Mac OS X")
    add_definitions ("-DOS_MACOSX -DHAVE_PCSC -DNEED_DAEMON")
    set (DEFAULT_CS_CONFDIR "/usr/local/etc")
elseif (OSCamOperatingSystem MATCHES "Tuxbox")
    set (DEFAULT_CS_CONFDIR "/var/tuxbox/config")
    if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
        add_definitions ("-DOS_LINUX -DTUXBOX -DMIPSEL")
    else (${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
        add_definitions ("-DOS_LINUX -DTUXBOX -DPPC")
    endif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
elseif (OSCamOperatingSystem MATCHES "TripleDragon")
    add_definitions ("-DOS_LINUX -DTRIPLEDRAGON -DSTB04SCI -DTUXBOX -DPPC")
    set (DEFAULT_CS_CONFDIR "/var/tuxbox/config")
elseif (OSCamOperatingSystem MATCHES "NeutrinoHD")
    add_definitions ("-DOS_LINUX -DTUXBOX -DCOOL")
    set (DEFAULT_CS_CONFDIR "/var/tuxbox/config")
elseif (OSCamOperatingSystem MATCHES "SlugOS")
    add_definitions ("-DOS_LINUX -DARM")
    set (DEFAULT_CS_CONFDIR "/var/etc")
elseif (OSCamOperatingSystem MATCHES "OpenWRT")
    if (CS_OS_HW MATCHES "dockstar")
        add_definitions ("-DOS_LINUX -DARM -DDOCKSTAR")
    else (CS_OS_HW MATCHES "dockstar")
        add_definitions ("-DOS_LINUX -DARM")
    endif (CS_OS_HW MATCHES "dockstar")
    set (DEFAULT_CS_CONFDIR "/usr/oscam")
elseif (OSCamOperatingSystem MATCHES "Fonera2")
    add_definitions ("-DOS_LINUX -DMIPSEL -DUCLIBC")
    set (DEFAULT_CS_CONFDIR "/var/etc")
elseif (OSCamOperatingSystem MATCHES "DIR-825")
    add_definitions ("-DOS_LINUX -DMIPSEL -DUCLIBC")
    set (DEFAULT_CS_CONFDIR "/var/etc")
elseif (OSCamOperatingSystem MATCHES "AZBox")
    add_definitions ("-DOS_LINUX -DMIPSEL -DAZBOX")
    set (DEFAULT_CS_CONFDIR "/PLUGINS/OpenXCAS/oscamCAS")
elseif (OSCamOperatingSystem MATCHES "agv2+w")
    add_definitions ("-DOS_LINUX -DUCLIBC")
    set (DEFAULT_CS_CONFDIR "/etc")
elseif (OSCamOperatingSystem MATCHES "WRT54G")
    add_definitions ("-DOS_LINUX -DMIPSEL -DUCLIBC -DUSE_GPIO")
    set (DEFAULT_CS_CONFDIR "/jffs/etc/config/oscam")
elseif (OSCamOperatingSystem MATCHES "Amino")
    add_definitions ("-DOS_LINUX -DSH4 -DTUXBOX")
    set (DEFAULT_CS_CONFDIR "/usr/local/etc")
elseif (OSCamOperatingSystem MATCHES "QboxHD")
    add_definitions ("-DOS_LINUX -DSH4 -DQBOXHD -DTUXBOX")
    set (DEFAULT_CS_CONFDIR "/var/tuxbox/config")
elseif (OSCamOperatingSystem MATCHES "Windows/Cygwin")
    add_definitions ("-DOS_CYGWIN32 -static -DHAVE_PCSC")
    set (DEFAULT_CS_CONFDIR ".")
elseif (OSCamOperatingSystem MATCHES "FreeBSD")
    add_definitions ("-DOS_FREEBSD")
    set (DEFAULT_CS_CONFDIR ".")
endif (OSCamOperatingSystem MATCHES "Linux")

set (CS_CONFDIR ${DEFAULT_CS_CONFDIR} CACHE STRING "Default path for the config files")
add_definitions ("-DCS_CONFDIR=\\\"${CS_CONFDIR}\\\"")

set (CS_OS_CPU ${CMAKE_SYSTEM_PROCESSOR})
set (CS_OSTYPE ${CS_OS_CPU}-${CS_OS_HW}-${CS_OS_SYS})

add_definitions ("-DUSE_CMAKE")
add_definitions ("-DCS_OSTYPE=\\\"${CS_OSTYPE}\\\"")
add_definitions ("-DCS_OS_CPU=\\\"${CS_OS_CPU}\\\"")
add_definitions ("-DCS_OS_HW=\\\"${CS_OS_HW}\\\"")
add_definitions ("-DCS_OS_SYS=\\\"${CS_OS_SYS}\\\"")

# Manage oscam-config.h based on command line parameters
# Manipulate config file based on given parameters and read unset parameters

# Available options
set(addons WEBIF HAVE_DVBAPI IRDETO_GUESSING CS_ANTICASC WITH_DEBUG CS_WITH_DOUBLECHECK CS_LED QBOXHD_LED CS_LOGHISTORY WITH_SSL)
set(protocols MODULE_CAMD33 MODULE_CAMD35 MODULE_CAMD35_TCP MODULE_NEWCAMD MODULE_CCCAM MODULE_RADEGAST MODULE_SERIAL MODULE_MONITOR MODULE_CONSTCW)
set(readers WITH_CARDREADER READER_NAGRA READER_IRDETO READER_CONAX READER_CRYPTOWORKS READER_SECA READER_VIACCESS READER_VIDEOGUARD READER_DRE READER_TONGFANG)

MACRO(GENERATE_OSCAM_CONFIG fullpath)
	file(READ ${fullpath} config)
	foreach(option ${addons} ${protocols} ${readers})
		if(DEFINED ${option})
			# Note: cmake does not read the file as individual lines but as a long
			#		string, hence we use \n instead of ^ to determine where a line begins

			if(${option})
				string(REGEX REPLACE "\n//#define ${option}" "\n#define ${option}" config ${config})
			else(${option})
				string(REGEX REPLACE "\n#define ${option}" "\n//#define ${option}" config ${config})
			endif(${option})
		else(DEFINED ${option})
			# read value from current oscam-config.h

			if(${config} MATCHES "\n#define ${option}")
				SET(${option} TRUE)
			endif(${config} MATCHES "\n#define ${option}")
		endif(DEFINED ${option})
	endforeach(option)
	file(WRITE ${fullpath} ${config})
ENDMACRO(GENERATE_OSCAM_CONFIG fullpath)

#----------------------- subdirectories ------------------------------

include (CheckIncludeFile)
GENERATE_OSCAM_CONFIG("${CMAKE_CURRENT_SOURCE_DIR}/oscam-config.h")

if(CS_WITH_GBOX)
    add_definitions ("-DCS_WITH_GBOX")
endif(CS_WITH_GBOX)

check_include_file ("pthread.h" HAVE_PTHREAD)
if (HAVE_PTHREAD)
    message(STATUS "  pthread found. Adding pthread support ")
    add_definitions ("-DHAVE_PTHREAD_H")
elseif (HAVE_PTHREAD)
    message(STATUS "  no pthread found. No smartreader ")
endif (HAVE_PTHREAD)

if (WITH_SSL)
check_include_file ("openssl/aes.h" HAVE_AES)
if (HAVE_AES)
    add_definitions ("-DHAVE_AES")
endif (HAVE_AES)

check_include_file ("openssl/sha.h" HAVE_SHA)
if (HAVE_SHA)
    add_definitions ("-DHAVE_SHA")
endif (HAVE_SHA)

find_package(OpenSSL QUIET)
if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "  openssl found.")
else (OPENSSL_FOUND)
    message(STATUS "  openssl not found.")
    if (WITH_SSL)
        message(FATAL "  ssl support requested but not found! ")
    endif (WITH_SSL)
endif (OPENSSL_FOUND)
if (WITH_SSL)

if (NOT OSCamOperatingSystem MATCHES "Mac OS X")
   if (LIBRTDIR)
        check_include_file ("${LIBRTDIR}/include/time.h" HAVE_LIBRT_STATIC)
        if (HAVE_LIBRT_STATIC)
            if (EXISTS ${LIBRTDIR}/lib/librt.a)
                message(STATUS "  static librt found : ${LIBRTDIR}/lib/librt.a (needed by libusb).")
                add_definitions ("-I${LIBRTDIR}/include/")
                add_library(imp_librt STATIC IMPORTED)
                set_property(TARGET imp_librt PROPERTY IMPORTED_LOCATION ${LIBRTDIR}/lib/librt.a)
            else (EXISTS ${LIBRTDIR}/lib/librt.a)
                message(STATUS " ${LIBRTDIR}/lib/librt.a not found (needed by libusb). No smartreader support)")
                unset (HAVE_LIBRT_STATIC)
            endif (EXISTS ${LIBRTDIR}/lib/librt.a)
        else (HAVE_LIBRT_STATIC)
            message(STATUS "  no librt found (needed by libusb). No smartreader support")
        endif (HAVE_LIBRT_STATIC)
    else (LIBRTDIR)
        check_include_file ("time.h" HAVE_LIBRT)
        if (HAVE_LIBRT)
            message(STATUS "  librt found (needed by libusb).")
        else (HAVE_LIBRT)
            message(STATUS "  no librt found (needed by libusb. No smartreader support")
        endif (HAVE_LIBRT)
    endif (LIBRTDIR)
else (NOT OSCamOperatingSystem MATCHES "Mac OS X")
    set (HAVE_LIBRT True)
endif (NOT OSCamOperatingSystem MATCHES "Mac OS X")


if( HAVE_LIBRT OR HAVE_LIBRT_STATIC)
    if (LIBUSBDIR)
        check_include_file ("${LIBUSBDIR}/include/libusb-1.0/libusb.h" HAVE_LIBUSB)
        if (HAVE_LIBUSB AND HAVE_PTHREAD)
            if (EXISTS ${LIBUSBDIR}/lib/libusb-1.0.a)
                message(STATUS "  static libusb 1.0 found (${LIBUSBDIR}/lib/libusb-1.0.a). Adding smartreader support ")
                add_definitions ("-DLIBUSB")
                add_definitions ("-I${LIBUSBDIR}/include/")
                add_library(imp_libusb STATIC IMPORTED)
                set_property(TARGET imp_libusb PROPERTY IMPORTED_LOCATION ${LIBUSBDIR}/lib/libusb-1.0.a)
            else (EXISTS ${LIBUSBDIR}/lib/libusb-1.0.a)
                message(STATUS "  static libusb 1.0 not found (${LIBUSBDIR}/lib/libusb-1.0.a). No smartreader support ")
                unset(HAVE_LIBUSB)
                unset(HAVE_LIBRT)
                unset(HAVE_LIBRT_STATIC)
            endif (EXISTS ${LIBUSBDIR}/lib/libusb-1.0.a)
        else (HAVE_LIBUSB AND HAVE_PTHREAD)
            message(STATUS "  no libusb 1.0 found. No smartreader support")
        endif (HAVE_LIBUSB AND HAVE_PTHREAD)
    else (LIBUSBDIR)
        check_include_file ("libusb-1.0/libusb.h" HAVE_LIBUSB)
        if (HAVE_LIBUSB AND HAVE_PTHREAD)
            if (EXISTS /usr/local/lib/libusb-1.0.a)
                message(STATUS "  static libusb 1.0 found : /usr/local/lib/libusb-1.0.a . Adding smartreader support ")
                add_definitions ("-DLIBUSB")
                add_definitions ("-I/usr/local/include")
                add_library(imp_libusb STATIC IMPORTED)
                set_property(TARGET imp_libusb PROPERTY IMPORTED_LOCATION /usr/local/lib/libusb-1.0.a)
            elseif (EXISTS /usr/lib/libusb-1.0.a)
                message(STATUS "  static libusb 1.0 found : /usr/lib/libusb-1.0.a . Adding smartreader support ")
                add_definitions ("-DLIBUSB")
                add_library(imp_libusb STATIC IMPORTED)
                set_property(TARGET imp_libusb PROPERTY IMPORTED_LOCATION /usr/lib/libusb-1.0.a)
            else (EXISTS /usr/local/lib/libusb-1.0.a)
                message(STATUS "  static libusb 1.0 not found (not in /usr/local/lib/ or /usr/lib/) . No smartreader support ")
                unset(HAVE_LIBUSB)
                unset(HAVE_LIBRT)
                unset(HAVE_LIBRT_STATIC)
            endif (EXISTS /usr/local/lib/libusb-1.0.a)
        else (HAVE_LIBUSB AND HAVE_PTHREAD)
            message(STATUS "  no libusb 1.0 found. No smartreader support")
        endif (HAVE_LIBUSB AND HAVE_PTHREAD)
    endif (LIBUSBDIR)
endif( HAVE_LIBRT OR HAVE_LIBRT_STATIC)


check_include_file ("PCSC/wintypes.h" HAVE_PCSC)
if (HAVE_PCSC)
    add_definitions ("-DHAVE_PCSC")
if (OSCamOperatingSystem MATCHES "Linux")
    add_definitions ("-I/usr/include/PCSC")
endif (OSCamOperatingSystem MATCHES "Linux")
else (HAVE_PCSC)
if (OSCamOperatingSystem MATCHES "Windows/Cygwin")
    add_definitions ("-Icygwin")
    set (HAVE_PCSC "1")
endif (OSCamOperatingSystem MATCHES "Windows/Cygwin")
endif (HAVE_PCSC)


#----------------------- subdirectories ------------------------------

add_subdirectory (csctapi)
add_subdirectory (cscrypt)
if(CS_WITH_GBOX)
    add_subdirectory (csgbox)
endif(CS_WITH_GBOX)
if( HAVE_LIBRT OR HAVE_LIBRT_STATIC)
    if (HAVE_LIBUSB)
        add_subdirectory (utils)
    endif (HAVE_LIBUSB)
endif( HAVE_LIBRT OR HAVE_LIBRT_STATIC)

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
if(CS_WITH_GBOX)
    target_link_libraries (${exe_name} ${csoscam} ${csmodules} ${csreaders} csctapi cscrypt csgbox)
else(CS_WITHGBOX)
    target_link_libraries (${exe_name} ${csoscam} ${csmodules} ${csreaders} csctapi cscrypt)
endif(CS_WITH_GBOX)
if(HAVE_LIBRT AND HAVE_LIBUSB)
    target_link_libraries (${exe_name} imp_libusb)
    if (NOT OSCamOperatingSystem MATCHES "Mac OS X")
        target_link_libraries (${exe_name} rt)
    endif (NOT OSCamOperatingSystem MATCHES "Mac OS X")
    if (OSCamOperatingSystem MATCHES "Windows/Cygwin")
        target_link_libraries (${exe_name} setupapi)
        target_link_libraries (${exe_name} ole32)
        target_link_libraries (${exe_name} shell32)
    endif (OSCamOperatingSystem MATCHES "Windows/Cygwin")
endif(HAVE_LIBRT AND HAVE_LIBUSB)

if (HAVE_LIBRT_STATIC AND HAVE_LIBUSB)
    target_link_libraries (${exe_name} imp_libusb)
    if (NOT OSCamOperatingSystem MATCHES "Mac OS X")
    target_link_libraries (${exe_name} imp_librt)
    endif (NOT OSCamOperatingSystem MATCHES "Mac OS X")
    if (OSCamOperatingSystem MATCHES "Windows/Cygwin")
        target_link_libraries (${exe_name} setupapi)
        target_link_libraries (${exe_name} ole32)
        target_link_libraries (${exe_name} shell32)
    endif (OSCamOperatingSystem MATCHES "Windows/Cygwin")
endif (HAVE_LIBRT_STATIC AND HAVE_LIBUSB)

if (HAVE_PTHREAD)
    target_link_libraries (${exe_name} pthread)
endif (HAVE_PTHREAD)

if (WITH_SSL)
    target_link_libraries (${exe_name} ssl)
endif (WITH_SSL)

if (HAVE_AES)
    target_link_libraries (${exe_name} crypto)
endif (HAVE_AES)

if (HAVE_PCSC)
if (NOT OSCamOperatingSystem MATCHES "Mac OS X")
if (NOT OSCamOperatingSystem MATCHES "Windows/Cygwin")
    target_link_libraries (${exe_name} pcsclite)
endif (NOT OSCamOperatingSystem MATCHES "Windows/Cygwin")
endif (NOT OSCamOperatingSystem MATCHES "Mac OS X")
endif (HAVE_PCSC)


add_dependencies (${exe_name} ${csoscam} ${csreaders} ${csmodules})

#----------------------- specific options ------------------------------

if (OSCamOperatingSystem MATCHES "Linux")
elseif (OSCamOperatingSystem MATCHES "Mac OS X")
    FIND_LIBRARY (PCSC_LIBRARY PCSC)
    message (STATUS "OS X system PCSC : ${PCSC_LIBRARY}")
    target_link_libraries ( ${exe_name} ${PCSC_LIBRARY})
    set (HAVE_PCSC "1")
    FIND_LIBRARY (IOKit_LIBRARY IOKit)
    target_link_libraries ( ${exe_name} ${IOKit_LIBRARY})
    FIND_LIBRARY (CoreFoundation_LIBRARY CoreFoundation)
    target_link_libraries ( ${exe_name} ${CoreFoundation_LIBRARY})
elseif (OSCamOperatingSystem MATCHES "Tuxbox")
    target_link_libraries ( ${exe_name} dl)
elseif (OSCamOperatingSystem MATCHES "TripleDragon")
    target_link_libraries ( ${exe_name} dl)
elseif (OSCamOperatingSystem MATCHES "SlugOS")
elseif (OSCamOperatingSystem MATCHES "OpenWRT")
elseif (OSCamOperatingSystem MATCHES "Fonera2")
elseif (OSCamOperatingSystem MATCHES "DIR-825")
elseif (OSCamOperatingSystem MATCHES "agv2+w")
elseif (OSCamOperatingSystem MATCHES "WRT54G")
elseif (OSCamOperatingSystem MATCHES "Amino")
elseif (OSCamOperatingSystem MATCHES "QboxHD")
elseif (OSCamOperatingSystem MATCHES "Windows/Cygwin")
    message (STATUS "Windows system PCSC : winscard.dll")
    target_link_libraries (${exe_name} winscard)
    target_link_libraries (${exe_name} setupapi )
    target_link_libraries (${exe_name} ole32)
    target_link_libraries (${exe_name} shell32)
elseif (OSCamOperatingSystem MATCHES "NeutrinoHD")
    target_link_libraries ( ${exe_name} rt nxp )
elseif (OSCamOperatingSystem MATCHES "AZBox")
    add_library(xcas STATIC IMPORTED)
    set_property(TARGET xcas PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/openxcas/libOpenXCASAPI.a)
    target_link_libraries(${exe_name} xcas)
endif (OSCamOperatingSystem MATCHES "Linux")

#----------------------- put svnversion in the build ------------------------------
# at every target rebuild, we re-build the oscam.c compilation...

# add the needed dependency
add_dependencies (${exe_name} svnversion)
add_dependencies (${csoscam} svnversion-log)

# how to re-build the files which printout the version
add_custom_target (
    svnversion
    ALL
    touch ${CMAKE_CURRENT_SOURCE_DIR}/oscam.c
)
add_custom_target (
    svnversion-log
    ALL
    touch ${CMAKE_CURRENT_SOURCE_DIR}/oscam-log.c
)

#if the svnversion program is absent, this will leave the SVN_REVISION string empty,
#but won't stop CMake.
execute_process (COMMAND "svnversion" "-n" "-c" "${CMAKE_CURRENT_SOURCE_DIR}" OUTPUT_VARIABLE OSCAM_SVN_REVISION)

if (OSCAM_SVN_REVISION)
    string (REGEX REPLACE "[0-9]+:" "" OSCAM_SVN_REVISION "${OSCAM_SVN_REVISION}")
    string (REPLACE "M" "" OSCAM_SVN_REVISION "${OSCAM_SVN_REVISION}")
    string (REPLACE "exported" "0" OSCAM_SVN_REVISION "${OSCAM_SVN_REVISION}")
else (OSCAM_SVN_REVISION)
    set (OSCAM_SVN_REVISION "0")
endif (OSCAM_SVN_REVISION)

# pass the version to the compilations as a define
add_definitions ("-D'CS_SVN_VERSION=\"${OSCAM_SVN_REVISION}\"'")

#----------------------- global compile and link options ------------------------------

# some optimisations
if (OSCamOperatingSystem MATCHES "Mac OS X")
    add_definitions ("-O2 -Winline -Wall -Wextra -finline-functions -fomit-frame-pointer -m32 -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk")
    set (CMAKE_C_FLAGS_DEBUG "-O0 -g -m32")
    set (CMAKE_CXX_FLAGS_DEBUG "-O0 -g -m32")
elseif (OSCAM_SYSTEM_NAME MATCHES "NSLU2")
    add_definitions ("-O2 -Winline -Wall -finline-functions -fomit-frame-pointer")
elseif (OSCAM_SYSTEM_NAME MATCHES "Dockstar")
    add_definitions ("-O2 -Winline -Wall -finline-functions -fomit-frame-pointer")
else (OSCamOperatingSystem MATCHES "Mac OS X")
    add_definitions ("-Winline -Wall -Wextra")
    set (CMAKE_C_FLAGS "-O2 -finline-functions -fomit-frame-pointer")
    set (CMAKE_C_FLAGS_DEBUG "-O0 -g")
    set (CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
endif (OSCamOperatingSystem MATCHES "Mac OS X")

# we don't want the '-rdynamic' in the link command
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

# we want to strip if not Debug build
if (OSCamOperatingSystem MATCHES "Mac OS X")
  if (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
    set (CMAKE_EXE_LINKER_FLAGS "-s -m32 -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk")
  else (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
    message (STATUS "  building with debug")
    set (CMAKE_EXE_LINKER_FLAGS "-ggdb -m32 -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk")
  endif (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
else (OSCamOperatingSystem MATCHES "Mac OS X")
  if (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
    set (CMAKE_EXE_LINKER_FLAGS "-s")
  else (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
    message (STATUS "  building with debug")
    set (CMAKE_EXE_LINKER_FLAGS "-ggdb")
  endif (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
endif (OSCamOperatingSystem MATCHES "Mac OS X")

if (OSCamOperatingSystem MATCHES "Windows/Cygwin")
    set (CMAKE_EXE_LINKER_FLAGS "--enable-stdcall-fixup")
endif (OSCamOperatingSystem MATCHES "Windows/Cygwin")

#----------------------- installation -----------------------------

file (GLOB config_files "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/oscam.*")
file (GLOB doc_files "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/txt/*.txt")
file (GLOB man1_files "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/man/*.1")
file (GLOB man5_files "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/man/*.5")
file (GLOB example_files "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/example/oscam.ac"
                         "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/example/oscam.cert"
                         "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/example/oscam.conf"
                         "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/example/oscam.guess"
                         "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/example/oscam.ird"
                         "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/example/oscam.server"
                         "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/example/oscam.services"
                         "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/example/oscam.srvid"
                         "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/doc/example/oscam.user")
file (GLOB monitor_files "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/monitor/mpcs*.sh"
                         "${CMAKE_CURRENT_SOURCE_DIR}/Distribution/monitor/mpcs*.tar")

install (PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${exe_name}${CMAKE_EXECUTABLE_SUFFIX} DESTINATION bin COMPONENT bin)
install (FILES ${config_files} DESTINATION etc COMPONENT config)
install (FILES ${doc_files} DESTINATION share/doc/oscam COMPONENT doc)
install (FILES ${man1_files} DESTINATION share/man/man1 COMPONENT doc)
install (FILES ${man5_files} DESTINATION share/man/man5 COMPONENT doc)
install (FILES ${example_files} DESTINATION share/doc/oscam/example COMPONENT doc)
install (FILES ${monitor_files} DESTINATION share/doc/oscam/monitor COMPONENT doc)

#----------------------- we can use CPack to build pacakges --------------------------

# get version from source file
execute_process (COMMAND grep CS_VERSION ${CMAKE_CURRENT_SOURCE_DIR}/globals.h
    OUTPUT_VARIABLE CS_VERSION)
string (REGEX REPLACE ".*\"\(.*\)\".*" "\\1" CS_VERSION ${CS_VERSION})
string (REGEX REPLACE "\(.*\)\\..*\\..*" "\\1" CPACK_PACKAGE_VERSION_MAJOR ${CS_VERSION})
string (REGEX REPLACE ".*\\.\(.*\)\\..*" "\\1" CPACK_PACKAGE_VERSION_MINOR ${CS_VERSION})
string (REGEX REPLACE ".*\\..*\\.\(.*\)" "\\1" CPACK_PACKAGE_VERSION_PATCH ${CS_VERSION})
set (CPACK_PACKAGE_VERSION
     "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

# compute my filename
set (CPACK_PACKAGE_FILE_NAME
     "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}-${CS_OSTYPE}")

# wich archive we want to generate
set (CPACK_GENERATOR "TGZ")

# what to put in the archive
set (CPACK_STRIP_FILES TRUE)
set (CPACK_COMPONENTS_ALL bin)# config doc)

# ok, we can now use CPack
include (CPack)

#----------------------- printout resume -----------------------------

message (STATUS "")
message (STATUS "  operating system: ${OSCamOperatingSystem}")
message (STATUS "  system type: ${CS_OSTYPE}")
message (STATUS "  system: ${CS_OS_SYS}")
message (STATUS "  cpu: ${CS_OS_CPU}")
message (STATUS "  hw: ${CS_OS_HW}")
if (HAVE_AES)
    message (STATUS "  use system aes functions")
else (HAVE_AES)
    message (STATUS "  use built-in aes functions")
endif (HAVE_AES)
if (HAVE_SHA)
    message (STATUS "  use system sha functions")
else (HAVE_SHA)
    message (STATUS "  use built-in sha functions")
endif (HAVE_SHA)
if (HAVE_PCSC)
    message (STATUS "  use system pcsc functions")
endif (HAVE_PCSC)
if (HAVE_PTHREAD)
    message (STATUS "  use system pthread functions")
endif (HAVE_PTHREAD)
if (HAVE_LIBUSB)
    message (STATUS "  use system libusb functions")
endif (HAVE_LIBUSB)
if(CS_WITH_GBOX)
    message (STATUS "  gbox protocol enabled")
endif(CS_WITH_GBOX)

message (STATUS "")