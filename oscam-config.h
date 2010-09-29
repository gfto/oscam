// ADDONS
#ifndef WEBIF
//#define WEBIF
#endif

#ifndef HAVE_DVBAPI
#if !defined(OS_CYGWIN32) && !defined(OS_HPUX) && !defined(OS_FREEBSD) && !defined(OS_MACOSX)
#define HAVE_DVBAPI
#endif
#endif

#ifndef IRDETO_GUESSING
//#define IRDETO_GUESSING
#endif

#ifndef CS_ANTICASC
#define CS_ANTICASC
#endif

#ifndef WITH_DEBUG
#define WITH_DEBUG
#endif

#ifndef CS_LED
//#define CS_LED
#endif

#ifndef CS_WITH_DOUBLECHECK
//#define CS_WITH_DOUBLECHECK
#endif

// MODULE
#ifndef MODULE_MONITOR
#define MODULE_MONITOR
#endif

#ifndef MODULE_CAMD33
#define MODULE_CAMD33
#endif

#ifndef MODULE_CAMD35
#define MODULE_CAMD35
#endif

#ifndef MODULE_CAMD35_TCP
#define MODULE_CAMD35_TCP
#endif

#ifndef MODULE_NEWCAMD
#define MODULE_NEWCAMD
#endif

#ifndef MODULE_CCCAM
#define MODULE_CCCAM
#endif

#ifndef MODULE_RADEGAST
#define MODULE_RADEGAST
#endif

#ifndef MODULE_SERIAL
#define MODULE_SERIAL
#endif

#ifndef MODULE_CONSTCW
#define MODULE_CONSTCW
#endif


// CARDREADER
#ifndef WITH_CARDREADER
#define WITH_CARDREADER
#endif


#ifdef WITH_CARDREADER
#ifndef READER_NAGRA
#define READER_NAGRA
#endif

#ifndef READER_IRDETO
#define READER_IRDETO
#endif

#ifndef READER_CONAX
#define READER_CONAX
#endif

#ifndef READER_CRYPTOWORKS
#define READER_CRYPTOWORKS
#endif

#ifndef READER_SECA
#define READER_SECA
#endif

#ifndef READER_VIACCESS
#define READER_VIACCESS
#endif

#ifndef READER_VIDEOGUARD
#define READER_VIDEOGUARD
#endif

#ifndef READER_DRE
#define READER_DRE
#endif

#ifndef READER_TONGFANG
#define READER_TONGFANG
#endif
#endif



#define CS_LOGHISTORY

#ifdef OS_FREEBSD
#  define NO_ENDIAN_H
#  define NO_FTIME
#endif

#ifdef TUXBOX
#  ifdef MIPSEL
#    define CS_LOGFILE "/dev/null"
#  else
#    define CS_LOGFILE "/dev/tty"
#  endif
#  define CS_EMBEDDED
#  ifndef QBOXHD
#      define CS_NOSHM
#  endif
#  define NO_FTIME
#  if !defined(COOL) && !defined(ST_LINUX)
#    define SCI_DEV 1
#  endif
#endif

#ifdef UCLIBC
#  define CS_EMBEDDED
#    define CS_NOSHM
#  define NO_FTIME
#endif

#ifdef OS_CYGWIN32
#  define CS_NOSHM
#  define CS_MMAPFILE "oscam.mem"
#  define CS_LOGFILE "/dev/tty"
#  define NO_ENDIAN_H
#endif

#ifdef OS_SOLARIS
#  define NO_ENDIAN_H
#  define NEED_DAEMON
#endif

#ifdef OS_OSF
#  define NO_ENDIAN_H
#  define NEED_DAEMON
#endif

#ifdef OS_AIX
#  define NO_ENDIAN_H
#  define NEED_DAEMON
#  define socklen_t unsigned long
#endif

#ifdef OS_IRIX
#  define NO_ENDIAN_H
#  define NEED_DAEMON
#  define socklen_t unsigned long
#endif

#ifdef OS_HPUX
#  define NO_ENDIAN_H
#  define NEED_DAEMON
#endif

#ifdef ARM
#  define CS_EMBEDDED
#  define CS_NOSHM
#  define NO_FTIME
#endif

//#ifdef ALIGNMENT
//#  define STRUCTS_PACKED
//#endif
