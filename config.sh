#!/bin/bash
tempfile=/tmp/test$$
tempfileconfig=/tmp/oscam-config.h
configfile=oscam-config.h
DIALOG=${DIALOG:-`which dialog`}

height=30
width=65
listheight=12

if [ -z "${DIALOG}" ]; then
	echo "Please install dialog package." 1>&2
	exit 1
fi

cp -f $configfile $tempfileconfig

addons="WEBIF HAVE_DVBAPI IRDETO_GUESSING CS_ANTICASC WITH_DEBUG CS_WITH_DOUBLECHECK CS_LED QBOXHD_LED CS_LOGHISTORY MODULE_MONITOR WITH_SSL WITH_LB"
protocols="MODULE_CAMD33 MODULE_CAMD35 MODULE_CAMD35_TCP MODULE_NEWCAMD MODULE_CCCAM MODULE_GBOX MODULE_RADEGAST MODULE_SERIAL MODULE_CONSTCW"
readers="WITH_CARDREADER READER_NAGRA READER_IRDETO READER_CONAX READER_CRYPTOWORKS READER_SECA READER_VIACCESS READER_VIDEOGUARD READER_DRE READER_TONGFANG"

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
		WEBIF				"Web Interface"		$(check_test "WEBIF") \
		HAVE_DVBAPI			"DVB API"			$(check_test "HAVE_DVBAPI") \
		IRDETO_GUESSING		"Irdeto guessing"	$(check_test "IRDETO_GUESSING") \
		CS_ANTICASC			"Anti cascading"	$(check_test "CS_ANTICASC") \
		WITH_DEBUG			"Debug messages"	$(check_test "WITH_DEBUG") \
		CS_WITH_DOUBLECHECK	"ECM doublecheck"	$(check_test "CS_WITH_DOUBLECHECK") \
		CS_LED				"LED"				$(check_test "CS_LED") \
		QBOXHD_LED			"QboxHD LED"		$(check_test "QBOXHD_LED") \
		CS_LOGHISTORY		"Log history"		$(check_test "CS_LOGHISTORY") \
		MODULE_MONITOR		"Monitor"			$(check_test "MODULE_MONITOR") \
		WITH_SSL			"OpenSSL support"	$(check_test "WITH_SSL") \
		WITH_LB			"Loadbalancer"	$(check_test "WITH_LB") \
		2> ${tempfile}

	opt=${?}
	if [ $opt != 0 ]; then return; fi

	disable_all "$addons"
	enable_package
}

menu_protocols() {
	${DIALOG} --checklist "\nChoose protocols:\n " $height $width $listheight \
		MODULE_CAMD33		"camd 3.3"		$(check_test "MODULE_CAMD33") \
		MODULE_CAMD35		"camd 3.5 UDP"	$(check_test "MODULE_CAMD35") \
		MODULE_CAMD35_TCP	"camd 3.5 TCP"	$(check_test "MODULE_CAMD35_TCP") \
		MODULE_NEWCAMD		"newcamd"		$(check_test "MODULE_NEWCAMD") \
		MODULE_CCCAM		"CCcam"			$(check_test "MODULE_CCCAM") \
		MODULE_GBOX			"gbox"			$(check_test "MODULE_GBOX") \
		MODULE_RADEGAST		"radegast"		$(check_test "MODULE_RADEGAST") \
		MODULE_SERIAL		"Serial"		$(check_test "MODULE_SERIAL") \
		MODULE_CONSTCW		"constant CW"	$(check_test "MODULE_CONSTCW") \
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
