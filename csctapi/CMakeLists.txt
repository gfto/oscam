project (csctapi)

file (GLOB csctapi_srcs "*.c")
file (GLOB csctapi_hdrs "*.h")


check_include_file ("pthread.h" HAVE_PTHREAD)
if (HAVE_PTHREAD)
    add_definitions ("-DHAVE_PTHREAD_H")
endif (HAVE_PTHREAD)

if (NOT OSCamOperatingSystem MATCHES "Mac OS X")
   if (LIBRTDIR)
        check_include_file ("${LIBRTDIR}/include/time.h" HAVE_LIBRT_STATIC)
        if (HAVE_LIBRT_STATIC)
            if (EXISTS ${LIBRTDIR}/lib/librt.a)
                add_definitions ("-I${LIBRTDIR}/include/")
            else (EXISTS ${LIBRTDIR}/lib/librt.a)
                unset (HAVE_LIBRT_STATIC)
            endif (EXISTS ${LIBRTDIR}/lib/librt.a)
        elseif (HAVE_LIBRT_STATIC)
            set (HAVE_LIBRT_STATIC False)
        endif (HAVE_LIBRT_STATIC)
    else (LIBRTDIR)
        check_include_file ("time.h" HAVE_LIBRT)
        if (HAVE_LIBRT)
            set (HAVE_LIBRT True)
        else (HAVE_LIBRT)
            set (HAVE_LIBRT False)
        endif (HAVE_LIBRT)
    endif (LIBRTDIR)
else (NOT OSCamOperatingSystem MATCHES "Mac OS X")
    set (HAVE_LIBRT True)
endif (NOT OSCamOperatingSystem MATCHES "Mac OS X")


check_include_file ("libusb-1.0/libusb.h" HAVE_LIBUSB)
if (HAVE_LIBUSB AND HAVE_PTHREAD AND HAVE_LIBRT OR HAVE_LIBRT_STATIC)
    add_definitions ("-DLIBUSB")
endif (HAVE_LIBUSB AND HAVE_PTHREAD AND HAVE_LIBRT OR HAVE_LIBRT_STATIC)


if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    add_definitions ("-O2 -Winline -Werror -finline-functions -fomit-frame-pointer -s -m32")
    SET( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32" )
else (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    add_definitions ("-O2 -Winline -Werror -finline-functions -fomit-frame-pointer -s")
endif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

set (lib_name "csctapi")
add_library (${lib_name} STATIC ${csctapi_srcs} ${csctapi_hdrs})

