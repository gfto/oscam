#!/bin/bash

WD=$(dirname $0)

addons="WEBIF HAVE_DVBAPI WITH_STAPI IRDETO_GUESSING CS_ANTICASC WITH_DEBUG MODULE_MONITOR WITH_SSL WITH_LB CS_CACHEEX LCDSUPPORT IPV6SUPPORT"
protocols="MODULE_CAMD33 MODULE_CAMD35 MODULE_CAMD35_TCP MODULE_NEWCAMD MODULE_CCCAM MODULE_GBOX MODULE_RADEGAST MODULE_SERIAL MODULE_CONSTCW MODULE_PANDORA"
readers="WITH_CARDREADER READER_NAGRA READER_IRDETO READER_CONAX READER_CRYPTOWORKS READER_SECA READER_VIACCESS READER_VIDEOGUARD READER_DRE READER_TONGFANG READER_BULCRYPT"

list_options() {
	PREFIX="$1"
	shift
	for OPT in $@
	do
		grep "^\#define $OPT$" oscam-config.h >/dev/null 2>/dev/null
		[ $? = 0 ] && echo -n "${OPT//$PREFIX/} "
	done
	echo
}

case "$1" in
	'-s'|'--show')
		shift
		case "$1" in
			'all')
				list_options "" $addons $protocols $readers
			;;
			'addons')
				list_options "" $addons
			;;
			'protocols')
				list_options "MODULE_" $protocols
			;;
			'readers')
				list_options "READER_" $readers
			;;
			*)
				echo "Unknown parameter: $1"
				exit 1
			;;
		esac
		exit 0
		;;
	'-e'|'--enabled')
		grep "^\#define $2$" oscam-config.h >/dev/null 2>/dev/null
		if [ $? = 0 ]; then
			echo "Y" && exit 0
		else
			echo "N" && exit 1
		fi
	;;
	'-d'|'--disabled')
		grep "^\#define $2$" oscam-config.h >/dev/null 2>/dev/null
		if [ $? = 1 ]; then
			echo "Y" && exit 0
		else
			echo "N" && exit 1
		fi
	;;
	'-v'|'--oscam-version')
		grep CS_VERSION $WD/globals.h | cut -d\" -f2
		exit 0
	;;
	'-r'|'--oscam-revision')
		(svnversion -n $WD 2>/dev/null || echo -n 0) | cut -d: -f1 | sed 's/[^0-9]*$//; s/^$/0/'
		exit 0
	;;
	'-h'|'--help')
		echo \
"OSCam config
Usage: `basename $0` [parameters]

 -s, --show [param]        Show enabled configuration options.
                           Possible params: all, addons, protocols, readers
 -e, --enabled [option]    Check if certain option is enabled.
 -d, --disabled [option]   Check if certain option is disabled.
 -v, --oscam-version       Display OSCam version.
 -r, --oscam-revision      Display OSCam SVN revision.
 -h, --help                Display this help text.
"
		exit 1
	;;
esac

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

check_test() {
	if [ "$(cat $tempfileconfig | grep "^#define $1$")" != "" ]; then
		echo "on"
	else
		echo "off"
	fi
}

disable_all() {
	for i in $1; do
		sed -i -e "s/^#define ${i}$/\/\/#define ${i}/g" $tempfileconfig
	done
}

enable_package() {
	for i in $(cat $tempfile); do
		strip=$(echo $i | sed "s/\"//g")
		sed -i -e "s/\/\/#define ${strip}$/#define ${strip}/g" $tempfileconfig
	done
}

print_components() {
	clear
	echo "You have selected the following components:"
	echo -e "\nAdd-ons:"
	for i in $addons; do
		printf "\t%-20s: %s\n" $i $(check_test "$i")
	done

	echo -e "\nProtocols:"
	for i in $protocols; do
		printf "\t%-20s: %s\n" $i $(check_test "$i")
	done

	echo -e "\nReaders:"
	for i in $readers; do
		printf "\t%-20s: %s\n" $i $(check_test "$i")
	done
	cp -f $tempfileconfig $configfile
}

menu_addons() {
	${DIALOG} --checklist "\nChoose add-ons:\n " $height $width $listheight \
		WEBIF				"Web Interface"				$(check_test "WEBIF") \
		HAVE_DVBAPI			"DVB API"					$(check_test "HAVE_DVBAPI") \
		WITH_STAPI			"STAPI (DVB API required)"	$(check_test "WITH_STAPI") \
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
		echo -n " \"WITH_CARDREADER\"" >> ${tempfile}
	fi
	disable_all "$readers"
	enable_package
}

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
		Add-ons) menu_addons;;
		Protocols) menu_protocols;;
		Reader) menu_reader;;
		Save) print_components; rm $tempfile; rm $tempfileconfig; exit;;
	esac
done
