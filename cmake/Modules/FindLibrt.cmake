# Try to find librt
# Once done this will define
#
#  LIBRT_FOUND - system has librt
#  LIBRT_INCLUDE_DIR - the librt include directory
#  LIBRT_LIBRARIES - the libraries needed to use librt
#  LIBRT_STATIC_LIBRARIES - static libraries of librt
#

IF(LIBRT_LIBRARIES)
   SET(Librt_FIND_QUIETLY TRUE)
ENDIF(LIBRT_LIBRARIES)

FIND_PATH(LIBRT_INCLUDE_DIR NAMES time.h PATHS
	${LIBRTDIR}/include/
)

FIND_LIBRARY(LIBRT_LIBRARIES rt)
FIND_FILE(LIBRT_STATIC_LIBRARIES librt.a PATHS
	${LIBRTDIR}/lib/
	/usr/local/lib64/
	/usr/local/lib/
	/usr/lib/i386-linux-gnu/
	/usr/lib/x86_64-linux-gnu/
	/usr/lib64/
	/usr/lib/
)

if(LIBRT_INCLUDE_DIR AND (LIBRT_LIBRARIES OR ${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
	set(LIBRT_FOUND TRUE CACHE INTERNAL "librt found")
	if(NOT Librt_FIND_QUIETLY)
		message(STATUS "Found librt: ${LIBRT_INCLUDE_DIR}, ${LIBRT_LIBRARIES}, ${LIBRT_STATIC_LIBARIES}")
	endif(NOT Librt_FIND_QUIETLY)
else(LIBRT_INCLUDE_DIR AND (LIBRT_LIBRARIES OR ${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
	set(LIBRT_FOUND FALSE CACHE INTERNAL "librt not found")
	if(NOT Librt_FIND_QUIETLY)
		message(STATUS "librt not found.")
	endif(NOT Librt_FIND_QUIETLY)
endif(LIBRT_INCLUDE_DIR AND (LIBRT_LIBRARIES OR ${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))

MARK_AS_ADVANCED(LIBRT_INCLUDE_DIR LIBRT_LIBRARIES LIBRT_STATIC_LIBRARIES)

