#ifndef OSCAM_CONFIG_H_
#define OSCAM_CONFIG_H_

#ifndef HAVE_DVBAPI
#if !defined(OS_CYGWIN32) && !defined(OS_HPUX) && !defined(OS_FREEBSD) && !defined(OS_MACOSX)
#define HAVE_DVBAPI
#endif
#endif

#define CS_ANTICASC

#define WITH_DEBUG

// MODULE
#define MODULE_MONITOR
#define MODULE_CAMD33
#define MODULE_CAMD35
#define MODULE_CAMD35_TCP
#define MODULE_NEWCAMD
#define MODULE_CCCAM
#define MODULE_RADEGAST
#define MODULE_SERIAL
#define MODULE_CONSTCW

// CARDREADER
#define WITH_CARDREADER

#ifdef WITH_CARDREADER
#define READER_NAGRA
#define READER_IRDETO
#define READER_CONAX
#define READER_CRYPTOWORKS
#define READER_SECA
#define READER_VIACCESS
#define READER_VIDEOGUARD
#define READER_DRE
#define READER_TONGFANG
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

#endif //OSCAM_CONFIG_H_
