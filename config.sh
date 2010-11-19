#!/bin/bash
tempfile=/tmp/test$$
configfile=oscam-config.h
DIALOG=${DIALOG:-`which dialog`}

height=30
width=65
listheight=10

if [ -z "${DIALOG}" ]; then
	echo "Please install the dialog package" 1>&2
	exit 1
fi

addons="WEBIF HAVE_DVBAPI IRDETO_GUESSING CS_ANTICASC WITH_DEBUG CS_WITH_DOUBLECHECK CS_LED QBOXHD_LED CS_LOGHISTORY WITH_SSL"
protocols="MODULE_CAMD33 MODULE_CAMD35 MODULE_CAMD35_TCP MODULE_NEWCAMD MODULE_CCCAM MODULE_RADEGAST MODULE_SERIAL MODULE_MONITOR MODULE_CONSTCW"
readers="WITH_CARDREADER READER_NAGRA READER_IRDETO READER_CONAX READER_CRYPTOWORKS READER_SECA READER_VIACCESS READER_VIDEOGUARD READER_DRE READER_TONGFANG"

check_test() {
	if [ "$(cat $configfile | grep "^#define $1$")" != "" ]; then
		echo "on"
	else
		echo "off"
	fi
}

disable_all() {
	for i in $1; do
		sed -i -e "s/^#define ${i}$/\/\/#define ${i}/g" $configfile
	done

}

enable_package() {
	for i in $(cat $tempfile); do
		strip=$(echo $i | sed "s/\"//g")
		sed -i -e "s/\/\/#define ${strip}$/#define ${strip}/g" $configfile
	done
}

print_components() {
	clear
	echo "You have selected the following components:"
	echo -e "\nAddons:"
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
}

menu_addons() {
	${DIALOG} --checklist "\nChoose Addons:\n " $height $width $listheight \
		WEBIF			"Webinterface"	$(check_test "WEBIF") \
		HAVE_DVBAPI		"DVB-API"		$(check_test "HAVE_DVBAPI") \
		IRDETO_GUESSING	"Irdeto Guessing"	$(check_test "IRDETO_GUESSING") \
		CS_ANTICASC		"Anti Cascadingg"	$(check_test "CS_ANTICASC") \
		WITH_DEBUG		"Debug messages"	$(check_test "WITH_DEBUG") \
		CS_WITH_DOUBLECHECK	"WITH_DOUBLECHECK"	$(check_test "CS_WITH_DOUBLECHECK") \
		CS_LED			"LED"			$(check_test "CS_LED") \
		QBOXHD_LED		"QboxHD LED"		$(check_test "QBOXHD_LED") \
		CS_LOGHISTORY		"Log History"		$(check_test "CS_LOGHISTORY") \
		WITH_SSL		"Use OpenSSL"		$(check_test "WITH_SSL") \
		2> ${tempfile}

	opt=${?}
	if [ $opt != 0 ]; then return; fi

	disable_all "$addons"
	enable_package
}

menu_protocols() {
	${DIALOG} --checklist "\nChoose Protocols:\n " $height $width $listheight \
		MODULE_CAMD33		"Camd3.3"	$(check_test "MODULE_CAMD33") \
		MODULE_CAMD35		"Camd3.5"	$(check_test "MODULE_CAMD35") \
		MODULE_CAMD35_TCP	"Camd3.5 TCP"	$(check_test "MODULE_CAMD35_TCP") \
		MODULE_NEWCAMD	"Newcamd"	$(check_test "MODULE_NEWCAMD") \
		MODULE_CCCAM		"CCCam"	$(check_test "MODULE_CCCAM") \
		MODULE_RADEGAST	"Radegast"	$(check_test "MODULE_RADEGAST") \
		MODULE_SERIAL		"Serial"	$(check_test "MODULE_SERIAL") \
		MODULE_MONITOR	"Monitor"	$(check_test "MODULE_MONITOR") \
		MODULE_CONSTCW	"Constcw"	$(check_test "MODULE_CONSTCW") \
		2> ${tempfile}

	opt=${?}
	if [ $opt != 0 ]; then return; fi

	disable_all "$protocols"
	enable_package
}

menu_reader() {
	${DIALOG} --checklist "\nChoose Reader:\n " $height $width $listheight \
		READER_NAGRA		"Nagravision"	$(check_test "READER_NAGRA") \
		READER_IRDETO		"Irdeto"	$(check_test "READER_IRDETO") \
		READER_CONAX		"Conax"	$(check_test "READER_CONAX") \
		READER_CRYPTOWORKS	"Cryptoworks"	$(check_test "READER_CRYPTOWORKS") \
		READER_SECA		"Seca"		$(check_test "READER_SECA") \
		READER_VIACCESS	"Viaccess"	$(check_test "READER_VIACCESS") \
		READER_VIDEOGUARD	"Videoguard"	$(check_test "READER_VIDEOGUARD") \
		READER_DRE		"Dre"		$(check_test "READER_DRE") \
		READER_TONGFANG		"Tongfang"		$(check_test "READER_TONGFANG") \
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
		Addons		"Addons" \
		Protocols	"Network Protocols" \
		Reader		"Card Reader" \
		Quit		"Quit" \
		2> ${tempfile}

	opt=${?}
	if [ $opt != 0 ]; then rm $tempfile; print_components; exit; fi

	menuitem=`cat $tempfile`
	case $menuitem in
       	Addons) menu_addons;;
		Protocols) menu_protocols;;
		Reader) menu_reader;;
		Quit) rm $tempfile; print_components; exit;;
	esac
done
