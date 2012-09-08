#!/bin/sh

addons="WEBIF HAVE_DVBAPI IRDETO_GUESSING CS_ANTICASC WITH_DEBUG MODULE_MONITOR WITH_SSL WITH_LB CS_CACHEEX LCDSUPPORT IPV6SUPPORT"
protocols="MODULE_CAMD33 MODULE_CAMD35 MODULE_CAMD35_TCP MODULE_NEWCAMD MODULE_CCCAM MODULE_GBOX MODULE_RADEGAST MODULE_SERIAL MODULE_CONSTCW MODULE_PANDORA"
readers="WITH_CARDREADER READER_NAGRA READER_IRDETO READER_CONAX READER_CRYPTOWORKS READER_SECA READER_VIACCESS READER_VIDEOGUARD READER_DRE READER_TONGFANG READER_BULCRYPT"

defconfig="
CONFIG_WEBIF=y
CONFIG_HAVE_DVBAPI=y
CONFIG_IRDETO_GUESSING=y
CONFIG_CS_ANTICASC=y
CONFIG_WITH_DEBUG=y
CONFIG_MODULE_MONITOR=y
# CONFIG_WITH_SSL=n
CONFIG_WITH_LB=y
CONFIG_CS_CACHEEX=y
# CONFIG_LCDSUPPORT=n
# CONFIG_IPV6SUPPORT=n
# CONFIG_MODULE_CAMD33=n
CONFIG_MODULE_CAMD35=y
CONFIG_MODULE_CAMD35_TCP=y
CONFIG_MODULE_NEWCAMD=y
CONFIG_MODULE_CCCAM=y
CONFIG_MODULE_GBOX=y
CONFIG_MODULE_RADEGAST=y
CONFIG_MODULE_SERIAL=y
CONFIG_MODULE_CONSTCW=y
CONFIG_MODULE_PANDORA=y
CONFIG_WITH_CARDREADER=y
CONFIG_READER_NAGRA=y
CONFIG_READER_IRDETO=y
CONFIG_READER_CONAX=y
CONFIG_READER_CRYPTOWORKS=y
CONFIG_READER_SECA=y
CONFIG_READER_VIACCESS=y
CONFIG_READER_VIDEOGUARD=y
CONFIG_READER_DRE=y
CONFIG_READER_TONGFANG=y
CONFIG_READER_BULCRYPT=y
"

usage() {
	echo \
"OSCam config
Usage: `basename $0` [parameters]

 -g, --gui                 Start interactive configuration

 -s, --show-enabled [param] Show enabled configuration options.
 -Z, --show-disabled [param] Show disabled configuration options.
 -S, --show-valid [param]  Show valid configuration options.
                           Possible params: all, addons, protocols, readers

 -l, --list-config         List active configuration variables.
 -e, --enabled [option]    Check if certain option is enabled.
 -d, --disabled [option]   Check if certain option is disabled.

 -E, --enable [option]     Enable config option.
 -D, --disable [option]    Disable config option.

    The following [option]s enable or disable multiple settings.
      all       - Everything.
      addons    - All addons.
      protocols - All protocols.
      readers   - All readers.

 -R, --restore             Restore default config.

 -v, --oscam-version       Display OSCam version.
 -r, --oscam-revision      Display OSCam SVN revision.

 -m, --make-config.mak     Create or update config.mak

 -O, --detect-osx-sdk-version  Find where OS X SDK is located

 -h, --help                Display this help text.

Examples:
  # Enable WEBIF and SSL
  ./config.sh --enable WEBIF WITH_SSL

  # Disable WEBIF but enable WITH_SSL
  ./config.sh --disable WEBIF --enable WITH_SSL

  # Restore defaults and disable WEBIF and READER_NAGRA
  ./config.sh --restore --disable WEBIF READER_NAGRA

  # Use default config with only one enabled reader
  ./config.sh --restore --disable readers --enable READER_BULCRYPT

  # Disable everything and enable webif one module and one card reader
  ./config.sh --disable all --enable WEBIF MODULE_NEWCAMD READER_BULCRYPT

Available options:
    addons: $addons
 protocols: $protocols
   readers: $readers
"
}

enabled() {
	grep "^\#define $1$" oscam-config.h >/dev/null 2>/dev/null
	return $?
}

disabled() {
	grep "^\#define $1$" oscam-config.h >/dev/null 2>/dev/null
	test $? = 0 && return 1
	return 0
}

enabled_all() {
	for opt ; do
		enabled $opt || return 1
	done
	return 0
}

disabled_all() {
	for opt ; do
		disabled $opt || return 1
	done
	return 0
}

enabled_any() {
	for opt ; do
		enabled $opt && return 0
	done
	return 1
}

disabled_any() {
	for opt ; do
		disabled $opt && return 0
	done
	return 1
}

list_enabled() {
	for OPT in $@
	do
		enabled $OPT && echo $OPT
	done
}

list_disabled() {
	for OPT in $@
	do
		disabled $OPT && echo $OPT
	done
}

valid_opt() {
	echo $addons $protocols $readers | grep -w "$1" >/dev/null
	return $?
}

enable_opt() {
	valid_opt $1 && disabled $1 && {
		sed -i.bak -e "s|//#define $1$|#define $1|g" oscam-config.h && rm oscam-config.h.bak
		echo "Enable $1"
	}
}

enable_opts() {
	for OPT in $@
	do
		enable_opt $OPT
	done
}

disable_opt() {
	valid_opt $1 && enabled $1 && {
		sed -i.bak -e "s|#define $1$|//#define $1|g" oscam-config.h && rm oscam-config.h.bak
		echo "Disable $1"
	}
}

disable_opts() {
	for OPT in $@
	do
		disable_opt $OPT
	done
}

get_opts() {
	OPTS=""
	case "$1" in
	'addons')    OPTS="$addons" ; ;;
	'protocols') OPTS="$protocols" ; ;;
	'readers')   OPTS="$readers" ; ;;
	*)           OPTS="$addons $protocols $readers" ; ;;
	esac
	echo $OPTS
}

check_test() {
	if [ "$(cat $tempfileconfig | grep "^#define $1$")" != "" ]; then
		echo "on"
	else
		echo "off"
	fi
}

disable_all() {
	for i in $1; do
		sed -i.bak -e "s/^#define ${i}$/\/\/#define ${i}/g" $tempfileconfig
	done
}

enable_package() {
	for i in $(cat $tempfile); do
		strip=$(echo $i | sed "s/\"//g")
		sed -i.bak -e "s/\/\/#define ${strip}$/#define ${strip}/g" $tempfileconfig
	done
}

print_components() {
	clear
	echo "You have selected the following components:"
	echo
	echo "Add-ons:"
	for i in $addons; do
		printf "\t%-20s: %s\n" $i $(check_test "$i")
	done

	echo
	echo "Protocols:"
	for i in $protocols; do
		printf "\t%-20s: %s\n" $i $(check_test "$i")
	done

	echo
	echo "Readers:"
	for i in $readers; do
		printf "\t%-20s: %s\n" $i $(check_test "$i")
	done
	cp -f $tempfileconfig $configfile
}

menu_addons() {
	${DIALOG} --checklist "\nChoose add-ons:\n " $height $width $listheight \
		WEBIF				"Web Interface"				$(check_test "WEBIF") \
		HAVE_DVBAPI			"DVB API"					$(check_test "HAVE_DVBAPI") \
		IRDETO_GUESSING		"Irdeto guessing"			$(check_test "IRDETO_GUESSING") \
		CS_ANTICASC			"Anti cascading"			$(check_test "CS_ANTICASC") \
		WITH_DEBUG			"Debug messages"			$(check_test "WITH_DEBUG") \
		MODULE_MONITOR		"Monitor"					$(check_test "MODULE_MONITOR") \
		WITH_SSL			"OpenSSL support"			$(check_test "WITH_SSL") \
		WITH_LB				"Loadbalancing"				$(check_test "WITH_LB") \
		CS_CACHEEX			"Cache exchange"			$(check_test "CS_CACHEEX") \
		LCDSUPPORT			"LCD support"				$(check_test "LCDSUPPORT") \
		IPV6SUPPORT			"IPv6 support (experimental)"		$(check_test "IPV6SUPPORT") \
		2> ${tempfile}

	opt=${?}
	if [ $opt != 0 ]; then return; fi

	disable_all "$addons"
	enable_package
}

menu_protocols() {
	${DIALOG} --checklist "\nChoose protocols:\n " $height $width $listheight \
		MODULE_CAMD33		"camd 3.3"		$(check_test "MODULE_CAMD33") \
		MODULE_CAMD35		"camd 3.5 UDP"	        $(check_test "MODULE_CAMD35") \
		MODULE_CAMD35_TCP	"camd 3.5 TCP"	        $(check_test "MODULE_CAMD35_TCP") \
		MODULE_NEWCAMD		"newcamd"		$(check_test "MODULE_NEWCAMD") \
		MODULE_CCCAM		"CCcam"			$(check_test "MODULE_CCCAM") \
		MODULE_GBOX		"gbox"  		$(check_test "MODULE_GBOX") \
		MODULE_RADEGAST		"radegast"		$(check_test "MODULE_RADEGAST") \
		MODULE_SERIAL		"Serial"		$(check_test "MODULE_SERIAL") \
		MODULE_CONSTCW		"constant CW"	        $(check_test "MODULE_CONSTCW") \
		MODULE_PANDORA		"Pandora"		$(check_test "MODULE_PANDORA") \
		2> ${tempfile}

	opt=${?}
	if [ $opt != 0 ]; then return; fi

	disable_all "$protocols"
	enable_package
}

menu_reader() {
	${DIALOG} --checklist "\nChoose reader:\n " $height $width $listheight \
		READER_NAGRA		"Nagravision"		$(check_test "READER_NAGRA") \
		READER_IRDETO		"Irdeto"			$(check_test "READER_IRDETO") \
		READER_CONAX		"Conax"				$(check_test "READER_CONAX") \
		READER_CRYPTOWORKS	"Cryptoworks"		$(check_test "READER_CRYPTOWORKS") \
		READER_SECA			"Seca"				$(check_test "READER_SECA") \
		READER_VIACCESS		"Viaccess"			$(check_test "READER_VIACCESS") \
		READER_VIDEOGUARD	"NDS Videoguard"	$(check_test "READER_VIDEOGUARD") \
		READER_DRE			"DRE Crypt"			$(check_test "READER_DRE") \
		READER_TONGFANG		"Tongfang"			$(check_test "READER_TONGFANG") \
		READER_BULCRYPT		"Bulcrypt"			$(check_test "READER_BULCRYPT") \
		2> ${tempfile}

	opt=${?}
	if [ $opt != 0 ]; then return; fi

	menuitem=`cat $tempfile`
	if [ "$menuitem" != "" ]; then
		printf " \"WITH_CARDREADER\"" >> ${tempfile}
	fi
	disable_all "$readers"
	enable_package
}

config_dialog() {
	tempfile=/tmp/test$$
	tempfileconfig=/tmp/oscam-config.h
	configfile=oscam-config.h
	DIALOG=${DIALOG:-`which dialog`}

	height=30
	width=65
	listheight=16

	if [ -z "${DIALOG}" ]; then
		echo "Please install dialog package." 1>&2
		exit 1
	fi

	cp -f $configfile $tempfileconfig

	while true; do
		${DIALOG} --menu "\nSelect category:\n " $height $width $listheight \
			Add-ons		"Add-ons" \
			Protocols	"Network protocols" \
			Reader		"Reader" \
			Save		"Save" \
			2> ${tempfile}

		opt=${?}
		if [ $opt != 0 ]; then clear; rm $tempfile; rm $tempfileconfig; exit; fi

		menuitem=`cat $tempfile`
		case $menuitem in
			Add-ons) menu_addons ;;
			Protocols) menu_protocols ;;
			Reader) menu_reader ;;
			Save)
				print_components
				rm $tempfile
				rm $tempfileconfig
				$0 --make-config.mak
				exit
			;;
		esac
	done
}

# Change working directory to the directory where the script is
cd $(dirname $0)

if [ $# = 0 ]
then
	usage
	exit 1
fi

while [ $# -gt 0 ]
do
	case "$1" in
	'-g'|'--gui'|'--config'|'--menuconfig')
		config_dialog
		break
	;;
	'-s'|'--show-enabled'|'--show')
		shift
		list_enabled $(get_opts $1)
		break
		;;
	'-Z'|'--show-disabled')
		shift
		list_disabled $(get_opts $1)
		break
		;;
	'-S'|'--show-valid')
		shift
		for OPT in $(get_opts $1)
		do
			echo $OPT
		done
		break
		;;
	'-E'|'--enable')
		shift
		while [ "$1" != "" ]
		do
			case "$1" in
			-*)
				$0 --make-config.mak
				continue 2
				;;
			all|addons|protocols|readers)
				enable_opts $(get_opts $1)
				;;
			*)
				enable_opt "$1"
				;;
			esac
			shift
		done
		$0 --make-config.mak
		;;
	'-D'|'--disable')
		shift
		while [ "$1" != "" ]
		do
			case "$1" in
			-*)
				$0 --make-config.mak
				continue 2
				;;
			all|addons|protocols|readers)
				disable_opts $(get_opts $1)
				;;
			*)
				disable_opt "$1"
				;;
			esac
			shift
		done
		$0 --make-config.mak
		;;
	'-R'|'--restore')
		echo $defconfig | sed -e 's|# ||g' | xargs printf "%s\n" | grep "=y$" | sed -e 's|^CONFIG_||g;s|=.*||g' |
		while read OPT
		do
			enable_opt "$OPT"
		done
		echo $defconfig | sed -e 's|# ||g' | xargs printf "%s\n" | grep "=n$" | sed -e 's|^CONFIG_||g;s|=.*||g' |
		while read OPT
		do
			disable_opt "$OPT"
		done
		$0 --make-config.mak
		;;
	'-e'|'--enabled')
		enabled $2 && echo "Y" && exit 0 || echo "N" && exit 1
		break
	;;
	'-d'|'--disabled')
		disabled $2 && echo "Y" && exit 0 || echo "N" && exit 1
		break
	;;
	'-v'|'--oscam-version')
		grep CS_VERSION globals.h | cut -d\" -f2
		break
	;;
	'-r'|'--oscam-revision')
		(svnversion -n . 2>/dev/null || printf 0) | sed 's/.*://; s/[^0-9]*$//; s/^$/0/'
		break
	;;
	'-O'|'--detect-osx-sdk-version')
		shift
		OSX_VER=${1:-10.8}
		for DIR in /Developer/SDKs/MacOSX{$OSX_VER,10.6,10.5}.sdk /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX{10.7,10,8,$OSX_VER}.sdk
		do
			if test -d $DIR
			then
				echo $DIR
				exit 0
			fi
		done
		echo Cant_find_OSX_SDK
		break
	;;
	'-l'|'--list-config')
		enabled_any $(get_opts readers) && enable_opt WITH_CARDREADER >/dev/null
		for OPT in $addons $protocols $readers
		do
			enabled $OPT && echo "CONFIG_$OPT=y" || echo "# CONFIG_$OPT=n"
		done
		# Calculate dependencies
		enabled MODULE_GBOX && echo "CONFIG_LIB_MINILZO=y" || echo "# CONFIG_LIB_MINILZO=n"
		enabled MODULE_CCCAM && echo "CONFIG_LIB_RC6=y" || echo "# CONFIG_LIB_RC6=n"
		enabled MODULE_CCCAM && echo "CONFIG_LIB_SHA1=y" || echo "# CONFIG_LIB_SHA1=n"
		enabled_any MODULE_NEWCAMD READER_DRE && echo "CONFIG_LIB_DES=y" || echo "# CONFIG_LIB_DES=n"
		enabled_any MODULE_CCCAM READER_NAGRA && echo "CONFIG_LIB_IDEA=y" || echo "# CONFIG_LIB_IDEA=n"
		enabled_any READER_CONAX READER_CRYPTOWORKS READER_NAGRA && echo "CONFIG_LIB_BIGNUM=y" || echo "# CONFIG_LIB_BIGNUM=n"
		exit 0
	;;
	'-m'|'--make-config.mak')
		$0 --list-config > config.mak.tmp
		cmp config.mak.tmp config.mak >/dev/null 2>/dev/null
		if [ $? != 0 ]
		then
			mv config.mak.tmp config.mak
		else
			rm config.mak.tmp
		fi
		exit 0
	;;
	'-h'|'--help')
		usage
		break
	;;
	*)
		echo "[WARN] Unknown parameter: $1" >&2
	;;
	esac
	# Some shells complain when there are no more parameters to shift
	test $# -gt 0 && shift
done

exit 0
