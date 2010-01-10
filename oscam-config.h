#define CS_LOGHISTORY
#define NO_PAR_SWITCH

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
#  define CS_NOSHM
#  define NO_FTIME
#  define CS_HW_DBOX2	1
#  define CS_HW_DREAM	2
#  ifndef COOL
#    define SCI_DEV 1
#  endif
#  ifndef NO_PAR_SWITCH
#    define NO_PAR_SWITCH
#  endif
#endif

#ifdef UCLIBC
#  define CS_EMBEDDED
#  define CS_NOSHM
#  define NO_FTIME
#  ifndef NO_PAR_SWITCH
#    define NO_PAR_SWITCH
#  endif
#endif

#ifdef OS_CYGWIN32
#  define CS_NOSHM
#  define CS_MMAPFILE "oscam.mem"
#  define CS_LOGFILE "/dev/tty"
#  define NO_ENDIAN_H
#  ifndef NO_PAR_SWITCH
#    define NO_PAR_SWITCH
#  endif
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
