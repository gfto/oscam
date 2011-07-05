#ifndef _TYPES_H_
#define _TYPES_H_

#if !defined(OS_AIX)
typedef unsigned char uchar;
#endif

#endif // _TYPES_H_

#ifndef NO_ENDIAN_H
 #ifdef OS_MACOSX
    #include <machine/endian.h>
    #define __BYTE_ORDER __DARWIN_BYTE_ORDER 
    #define __BIG_ENDIAN    __DARWIN_BIG_ENDIAN 
    #define __LITTLE_ENDIAN __DARWIN_LITTLE_ENDIAN
 #elif defined OS_FREEBSD
    #include <sys/endian.h>
    #define __BYTE_ORDER _BYTE_ORDER
    #define __BIG_ENDIAN    _BIG_ENDIAN
    #define __LITTLE_ENDIAN _LITTLE_ENDIAN
 #else
    #include <endian.h>
    #include <byteswap.h>
 #endif
#endif

#if defined(CS_EMBEDDED) || defined(OS_LINUX)

#ifdef ntohl
#undef ntohl
#endif
#ifdef ntohs
#undef ntohs
#endif
#ifdef htonl
#undef htonl
#endif
#ifdef htons
#undef htons
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#  define ntohl(x)	(x)
#  define ntohs(x)	(x)
#  define htonl(x)	(x)
#  define htons(x)	(x)
#else
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#    define ntohl(x)	__bswap_32 (x)
#    define ntohs(x)	__bswap_16 (x)
#    define htonl(x)	__bswap_32 (x)
#    define htons(x)	__bswap_16 (x)
#  endif
#endif

#endif // CS_EMBEDDED || OS_LINUX
