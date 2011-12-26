# Try to find libusb1
# Once done this will define
#
#  LIBUSB_FOUND - system has libusb-1.0
#  LIBUSB_INCLUDE_DIR - the libusb-1.0 include directory
#  LIBUSB_LIBRARIES - the libraries needed to use libusb-1.0
#  LIBUSB_STATIC_LIBRARIES - static libraries of libusb-1.0
#

IF(LIBUSB_LIBRARIES)
   SET(Libusb_FIND_QUIETLY TRUE)
ENDIF(LIBUSB_LIBRARIES)

FIND_PATH(LIBUSB_INCLUDE_DIR NAMES libusb-1.0/libusb.h PATHS
	${LIBUSBDIR}/include/
)

FIND_LIBRARY(LIBUSB_LIBRARIES usb-1.0)
FIND_FILE(LIBUSB_STATIC_LIBRARIES libusb-1.0.a PATHS
	${LIBUSBDIR}/lib/
	/usr/local/lib64/
	/usr/local/lib/
	/usr/lib/i386-linux-gnu/
	/usr/lib/x86_64-linux-gnu/
	/usr/lib64/
	/usr/lib/
)

if(LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)
	set(LIBUSB_FOUND TRUE CACHE INTERNAL "libusb-1.0 found")
	if(NOT Libusb_FIND_QUIETLY)
		message(STATUS "Found libusb-1.0: ${LIBUSB_INCLUDE_DIR}, ${LIBUSB_LIBRARIES}, ${LIBUSB_STATIC_LIBARIES}")
	endif(NOT Libusb_FIND_QUIETLY)
else(LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)
	set(LIBUSB_FOUND FALSE CACHE INTERNAL "libusb-1.0 not found")
	if(NOT Libusb_FIND_QUIETLY)
		message(STATUS "libusb-1.0 not found.")
	endif(NOT Libusb_FIND_QUIETLY)
endif(LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)

MARK_AS_ADVANCED(LIBUSB_INCLUDE_DIR LIBUSB_LIBRARIES LIBUSB_STATIC_LIBRARIES)

