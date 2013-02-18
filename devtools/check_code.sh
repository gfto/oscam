#!/bin/sh

if [ ! -f globals.h ]
then
	echo "ERROR: Run this script in the oscam source directory (where globals.h file is)."
	exit 1
fi

check_func() {
	func="$1"
	MSG="$2"
	find . -name '*.c' -print0 | xargs -0 grep -w $func | grep $func\( | grep -v "This is safe" |
	while read LINE
	do
		echo " *** $MSG"
		echo "$LINE"
	done
}

check_func strcpy            UNSAFE_STRCPY_USE_CS_STRNCPY_INSTEAD
check_func sprintf           UNSAFE_SPRINTF_USE_SNPRINTF_INSTEAD
check_func strtok            UNSAFE_STRTOK_USE_STRTOK_R_INSTEAD
check_func gmtime            UNSAFE_GMTIME_NOT_THREADSAFE_USE_CS_GMTIME_R
check_func localtime         UNSAFE_LOCALTIME_NOT_THREADSAFE_USE_LOCALTIME_R
check_func asctime           UNSAFE_ASCTIME_NOT_THREADSAFE_USE_ASCTIME_R
check_func ctime             UNSAFE_CTIME_NOT_THREADSAFE_USE_CS_CTIME_R
check_func gethostbyaddr     UNSAFE_GETHOSTBYADDR_NOT_THREADSAFE_USE_GETADDRINFO
check_func gethostent        UNSAFE_GETHOSTENT_NOT_THREADSAFE
check_func getprotobyname    UNSAFE_GETPROTOBYNAME_NOT_THREADSAFE_USE_GETPROTOBYNAME_R
check_func getservbyname     UNSAFE_GETSERVBYNAME_NOT_THREADSAFE_USE_GETSERVBYNAME_R
check_func getservbyport     UNSAFE_GETSERVBYPORT_NOT_THREADSAFE_USE_GETSERVBYPORT_R
check_func getservent        UNSAFE_GETSERVENT_NOT_THREADSAFE_USE_GETSERVENT_R
check_func getnetbyname      UNSAFE_GETNETBYNAME_NOT_THREADSAFE_USE_GETNETBYNAME_R
check_func getnetbyaddr      UNSAFE_GETNETBYADDR_NOT_THREADSAFE_USE_GETNETBYADDR_R
check_func getnetent         UNSAFE_GETNETENT_NOT_THREADSAFE_USE_GETNETENT_R
check_func getrpcbyname      UNSAFE_GETRPCBYNAME_NOT_THREADSAFE_USE_GETRPCBYNAME_R
check_func getrpcbynumber    UNSAFE_GETRPCBYNUMBER_NOT_THREADSAFE_USE_GETRPCBYNUMBER_R
check_func getrpcent         UNSAFE_GETRPCENT_NOT_THREADSAFE_USE_GETRPCENT_R
check_func ctermid           UNSAFE_CTERMID_NOT_THREADSAFE_USE_CTERMID_R
check_func tmpnam            UNSAFE_TMPNAM_NOT_THREADSAFE
check_func tempnam           UNSAFE_TEMPNAM_NOT_THREADSAFE
check_func getlogin          UNSAFE_GETLOGIN_NOT_THREADSAFE_USE_GETLOGIN_R
check_func getpwnam          UNSAFE_GETPWNAM_NOT_THREADSAFE_USE_GETPWNAM_R
check_func getpwent          UNSAFE_GETPWENT_NOT_THREADSAFE_USE_GETPWENT_R
check_func fgetpwent         UNSAFE_FGETPWENT_NOT_THREADSAFE_USE_FGETPWENT_R
check_func getpwuid          UNSAFE_GETPWUID_NOT_THREADSAFE_USE_GETPWUID_R
check_func getspent          UNSAFE_GETSPENT_NOT_THREADSAFE_USE_GETSPENT_R
check_func getspnam          UNSAFE_GETSPNAM_NOT_THREADSAFE_USE_GETSPNAM_R
check_func fgetspent         UNSAFE_FGETSPENT_NOT_THREADSAFE_USE_FGETSPENT_R
check_func getgrnam          UNSAFE_GETGRNAM_NOT_THREADSAFE_USE_GETGRNAM_R
check_func getgrent          UNSAFE_GETGRENT_NOT_THREADSAFE_USE_GETGRENT_R
check_func getgrgid          UNSAFE_GETGRGID_NOT_THREADSAFE_USE_GETGRGID_R
check_func fgetgrent         UNSAFE_FGETGRENT_NOT_THREADSAFE_USE_FGETGRGID_R
check_func fcvt              UNSAFE_FCVT_NOT_THREADSAFE_AND_DEPRECATED
check_func ecvt              UNSAFE_ECVT_NOT_THREADSAFE_AND_DEPRECATED
check_func gcvt              UNSAFE_GCVT_NOT_THREADSAFE_AND_DEPRECATED
check_func strptime          STRPTIME_NOT_EXISTS_ON_SOME_DM500_DB2
check_func ftime             FTIME_DEPRECATED
check_func timegm            TIMEGM_GNU_SPECIFIC_USE_CS_TIMEGM
