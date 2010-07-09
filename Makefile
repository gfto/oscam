SHELL	= /bin/sh

VER	= $(subst ",,$(filter-out \#define CS_VERSION,$(shell grep CS_VERSION globals.h)))$(shell test -f `which svnversion` && svnversion -n . | awk 'BEGIN {FS = ":"} {print $$1}' | sed 's/[MS]$$//' | sed 's/exported/0/' || echo -n 0 )
SVN_REV=""$(shell test -f `which svnversion` && svnversion -n . | awk 'BEGIN {FS = ":"} {print $$1}' | sed 's/[MS]$$//' | sed 's/exported/0/' || echo -n 0 )""

CS_CONFDIR = '\"/usr/local/etc\"'

export VER

linux:	i386-pc-linux
linux-pcsc:	i386-pc-linux-pcsc
freebsd:	i386-pc-freebsd
tuxbox:	cross-powerpc-tuxbox-linux
tripledragon: cross-powerpc-405-linux
win:	cross-i386-pc-cygwin
cygwin: i386-pc-cygwin
macosx: macosx-native

std:	linux \
	macosx \
	cross-i386-pc-cygwin \
	cross-powerpc-tuxbox-linux \
	cross-powerpc-405-linux \
	cross-i386-pc-freebsd \
	cross-arm-nslu2-linux \
	cross-mipsel-router-linux-uclibc927 \
	cross-mipsel-router-linux-uclibc928 \
	cross-mipsel-router-linux-uclibc929 \
	cross-mipsel-router-linux-uclibc929-static \
	cross-mipsel-tuxbox-linux-glibc \
	cross-mipsel-fonera2 \
	cross-sh4-linux

all:	\
	cross-sparc-sun-solaris2.7 \
	cross-rs6000-ibm-aix4.2 \
	cross-mips-sgi-irix6.5


dist:	std
	@cd Distribution && tar cvf "../oscam$(VER).tar" *
	@bzip2 -9f "oscam$(VER).tar"

extra:	all
	@cd Distribution && tar cvf "../oscam$(VER)-extra.tar" *
	@bzip2 -9f "oscam$(VER)-extra.tar"

clean:
	@-rm -rf oscam-ostype.h lib Distribution/oscam-*

tar:	clean
	@tar cvf "oscam$(VER)-src.tar" Distribution Make* *.c *.h cscrypt csctapi
	@bzip2 -9f "oscam$(VER)-src.tar"

nptar:	clean
	@tar cvf "oscam$(VER)-nonpublic-src.tar" Distribution Make* *.c *.np *.h cscrypt csctapi csgbox
	@bzip2 -9f "oscam$(VER)-nonpublic-src.tar"

######################################################################
#
#	LINUX native
#
######################################################################
i386-pc-linux:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst i386,$(shell uname --machine),$(subst cross-,,$@)) \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DCS_CONFDIR=${CS_CONFDIR} -Winline -Wall -Wextra -finline-functions -fomit-frame-pointer -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip
######################################################################
#
#	LINUX native with libusb (smartreader)
#
######################################################################
i386-pc-linux-libusb:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst i386,$(shell uname --machine),$(subst cross-,,$@)) \
        	LIBUSB="/usr/local/lib/libusb-1.0.a" \
		OS_LIBS="-lcrypto -lm -lrt" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DLIBUSB -DCS_CONFDIR=${CS_CONFDIR} -Winline -Wall -Wextra -finline-functions -fomit-frame-pointer -D'CS_SVN_VERSION="\"$(SVN_REV)\""' -I/usr/local/include" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip

######################################################################
#
#	LINUX native with PCSC
#
######################################################################
i386-pc-linux-pcsc:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst i386,$(shell uname --machine),$(subst cross-,,$@)) \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread -lpcsclite" \
		DS_OPTS="-O2 -DOS_LINUX -DCS_CONFDIR=${CS_CONFDIR} -DHAVE_PCSC=1 -I/usr/include/PCSC -Winline -Wall -Wextra -finline-functions -fomit-frame-pointer -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip

######################################################################
#
#	LINUX native with PCSC & libusb (smartreader)
#
######################################################################
i386-pc-linux-pcsc-libusb:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst i386,$(shell uname --machine),$(subst cross-,,$@)) \
        	LIBUSB="/usr/local/lib/libusb-1.0.a" \
		OS_LIBS="-lcrypto -lm -lrt" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread -lpcsclite" \
		DS_OPTS="-O2 -DOS_LINUX -DLIBUSB -DCS_CONFDIR=${CS_CONFDIR} -DHAVE_PCSC=1 -I/usr/include/PCSC -Winline -Wall -Wextra -finline-functions -fomit-frame-pointer -D'CS_SVN_VERSION="\"$(SVN_REV)\""' -I/usr/local/include" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip

######################################################################
#
#       MacOSX native
#
######################################################################
macosx-native:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_MACOSX -DNEED_DAEMON -DCS_NOSHM -DHAVE_PTHREAD_H -DCS_CONFDIR=${CS_CONFDIR} -DHAVE_PCSC=1 -m32 -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk -Winline -Wall -Wextra -finline-functions -fomit-frame-pointer -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="-framework PCSC -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip

######################################################################
#
#       MacOSX native with libusb (smartreader)
#
######################################################################
macosx-libusb:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		LIBUSB="/usr/local/lib/libusb-1.0.a" \
		OS_LIBS="-lcrypto -lm " \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_MACOSX -DNEED_DAEMON -DCS_NOSHM -DHAVE_PTHREAD_H  -DCS_CONFDIR=${CS_CONFDIR} -DHAVE_PCSC=1 -DLIBUSB -m32 -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk -Winline -Wall -Wextra -finline-functions -fomit-frame-pointer -D'CS_SVN_VERSION="\"$(SVN_REV)\""' -I/usr/local/include" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="-framework PCSC -mmacosx-version-min=10.5 -isysroot /Developer/SDKs/MacOSX10.5.sdk -Wl,-framework -Wl,IOKit -Wl,-framework -Wl,CoreFoundation -Wl,-prebind -no-undefined" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip


######################################################################
#
#	FreeBSD native
#
######################################################################
i386-pc-freebsd:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_FREEBSD -DBSD_COMP  -DCS_CONFDIR=${CS_CONFDIR} -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip

######################################################################
#
#	FreeBSD 5.4 crosscompiler
#
######################################################################
cross-i386-pc-freebsd:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_FREEBSD -DBSD_COMP -DCS_CONFDIR=${CS_CONFDIR} -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=i386-pc-freebsd5.4-gcc \
		DS_AR=i386-pc-freebsd5.4-ar \
		DS_LD=i386-pc-freebsd5.4-ld \
		DS_RL=i386-pc-freebsd5.4-ranlib \
		DS_ST=i386-pc-freebsd5.4-strip

######################################################################
#
#	Tuxbox crosscompiler
#
######################################################################
cross-powerpc-tuxbox-linux:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -ldl -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DTUXBOX -DPPC -DCS_CONFDIR='\"/var/tuxbox/config\"' -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=powerpc-tuxbox-linux-gnu-gcc \
		DS_AR=powerpc-tuxbox-linux-gnu-ar \
		DS_LD=powerpc-tuxbox-linux-gnu-ld \
		DS_RL=powerpc-tuxbox-linux-gnu-ranlib \
		DS_ST=powerpc-tuxbox-linux-gnu-strip

cross-powerpc-tuxbox-linux-uclibc:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DTUXBOX -DPPC -DCS_CONFDIR='\"/var/tuxbox/config\"' -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=powerpc-tuxbox-linux-uclibc-gcc \
		DS_AR=powerpc-tuxbox-linux-uclibc-ar \
		DS_LD=powerpc-tuxbox-linux-uclibc-ld \
		DS_RL=powerpc-tuxbox-linux-uclibc-ranlib \
		DS_ST=powerpc-tuxbox-linux-uclibc-strip

######################################################################
#
#	TripleDragon crosscompiler
#
######################################################################
cross-powerpc-405-linux:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -ldl -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DTRIPLEDRAGON -DCS_LOGHISTORY -DCS_ANTICASC -DSTB04SCI -DCS_CONFDIR='\"/var/tuxbox/config\"' -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=powerpc-405-linux-gnu-gcc \
		DS_AR=powerpc-405-linux-gnu-ar \
		DS_LD=powerpc-405-linux-gnu-ld \
		DS_RL=powerpc-405-linux-gnu-ranlib \
		DS_ST=powerpc-405-linux-gnu-strip

######################################################################
#
#	sh4 crosscompiler
#
######################################################################
cross-sh4-linux:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DSH4 -DTUXBOX -DCS_CONFDIR='\"/var/tuxbox/config\"' -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=/opt/STM/STLinux-2.0/devkit/sh4/bin/sh4-linux-gcc \
		DS_AR=/opt/STM/STLinux-2.0/devkit/sh4/bin/sh4-linux-ar \
		DS_LD=/opt/STM/STLinux-2.0/devkit/sh4/bin/sh4-linux-ld \
		DS_RL=/opt/STM/STLinux-2.0/devkit/sh4/bin/sh4-linux-ranlib \
		DS_ST=/opt/STM/STLinux-2.0/devkit/sh4/bin/sh4-linux-strip

######################################################################
#
#	Cygwin crosscompiler
#
######################################################################
cross-i386-pc-cygwin:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_CYGWIN32 -DCS_CONFDIR=${CS_CONFDIR} -static -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=i686-pc-cygwin-gcc \
		DS_AR=i686-pc-cygwin-ar \
		DS_LD=i686-pc-cygwin-ld \
		DS_RL=i686-pc-cygwin-ranlib \
		DS_ST=i686-pc-cygwin-strip

######################################################################
#
#	Cygwin native
#
######################################################################
i386-pc-cygwin:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_CYGWIN32 -DCS_CONFDIR=${CS_CONFDIR} -I /tmp/include -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip


######################################################################
#
#	Cygwin native with PCSC
#
# 	requires Visual Studio / Visual C++ for the winscard includes
######################################################################
i386-pc-cygwin-pcsc:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		LIBPCSC="cygwin/libwinscard.a" \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_CYGWIN32 -D_WIN32 -DCS_CONFDIR=${CS_CONFDIR} -DHAVE_PCSC=1 -I /tmp/include -I ./cygwin -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip

######################################################################
#
#	Cygwin native with libusb
#
# 	requires Visual Studio / Visual C++ for the winscard includes
######################################################################
i386-pc-cygwin-libusb:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		LIBUSB="/usr/lib/libusb-1.0.a" \
		OS_LIBS="-lcrypto -lm -lSetupAPI -lOle32 -lshell32" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_CYGWIN32 -D_WIN32 -DLIBUSB -DCS_CONFDIR=${CS_CONFDIR} -I /tmp/include -I ./cygwin -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip


######################################################################
#
#	Solaris 7 crosscompiler
#
######################################################################
cross-sparc-sun-solaris2.7:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_SOLARIS -DOS_SOLARIS7 -DBSD_COMP -DCS_CONFDIR=${CS_CONFDIR} -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="-lsocket" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=sparc-sun-solaris2.7-gcc \
		DS_AR=sparc-sun-solaris2.7-ar \
		DS_LD=sparc-sun-solaris2.7-ld \
		DS_RL=sparc-sun-solaris2.7-ranlib \
		DS_ST=sparc-sun-solaris2.7-strip

######################################################################
#
#	OpenSolaris native compiler
#
######################################################################
opensolaris:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -lnsl -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_SOLARIS -DOS_SOLARIS7 -DBSD_COMP -DCS_CONFDIR=${CS_CONFDIR} -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="-lsocket" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip

######################################################################
#
#	AIX 4.2 crosscompiler
#
######################################################################
cross-rs6000-ibm-aix4.2:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthreads" \
		DS_OPTS="-O2 -DOS_AIX -DOS_AIX42 -DCS_CONFDIR=${CS_CONFDIR} -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=rs6000-ibm-aix4.2-gcc \
		DS_AR=rs6000-ibm-aix4.2-ar \
		DS_LD=rs6000-ibm-aix4.2-ld \
		DS_RL=rs6000-ibm-aix4.2-ranlib \
		DS_ST=rs6000-ibm-aix4.2-strip

######################################################################
#
#	IRIX 6.5 crosscompiler
#
######################################################################
cross-mips-sgi-irix6.5:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_IRIX -DOS_IRIX65 -DCS_CONFDIR=${CS_CONFDIR} -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=mips-sgi-irix6.5-gcc \
		DS_AR=mips-sgi-irix6.5-ar \
		DS_LD=mips-sgi-irix6.5-ld \
		DS_RL=mips-sgi-irix6.5-ranlib \
		DS_ST=mips-sgi-irix6.5-strip

######################################################################
#
#	Linux MIPS(LE) crosscompiler with ucLibc 0.9.27
#
######################################################################
cross-mipsel-router-linux-uclibc927:
	@-mipsel-linux-uclibc-setlib 0.9.27
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DMIPSEL -DUCLIBC -DUSE_GPIO -DCS_CONFDIR=${CS_CONFDIR} -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=mipsel-linux-uclibc-gcc \
		DS_AR=mipsel-linux-uclibc-ar \
		DS_LD=mipsel-linux-uclibc-ld \
		DS_RL=mipsel-linux-uclibc-ranlib \
		DS_ST=mipsel-linux-uclibc-strip

######################################################################
#
#	Linux MIPS(LE) crosscompiler with ucLibc 0.9.28
#
######################################################################
cross-mipsel-router-linux-uclibc928:
	@-mipsel-linux-uclibc-setlib 0.9.28
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DMIPSEL -DUCLIBC -DUSE_GPIO -DCS_CONFDIR=${CS_CONFDIR} -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=mipsel-linux-uclibc-gcc \
		DS_AR=mipsel-linux-uclibc-ar \
		DS_LD=mipsel-linux-uclibc-ld \
		DS_RL=mipsel-linux-uclibc-ranlib \
		DS_ST=mipsel-linux-uclibc-strip

######################################################################
#
#	Linux MIPS(LE) crosscompiler with ucLibc 0.9.29
#
######################################################################
cross-mipsel-router-linux-uclibc929:
	@-mipsel-linux-uclibc-setlib 0.9.29
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DMIPSEL -DUCLIBC -DUSE_GPIO -DCS_CONFDIR=${CS_CONFDIR} -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=mipsel-linux-uclibc-gcc \
		DS_AR=mipsel-linux-uclibc-ar \
		DS_LD=mipsel-linux-uclibc-ld \
		DS_RL=mipsel-linux-uclibc-ranlib \
		DS_ST=mipsel-linux-uclibc-strip

######################################################################
#
#	Linux MIPS(LE) crosscompiler with ucLibc 0.9.29 (static)
#
######################################################################
cross-mipsel-router-linux-uclibc929-static:
	@-mipsel-linux-uclibc-setlib 0.9.29
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DMIPSEL -DUCLIBC -DUSE_GPIO -DCS_CONFDIR=${CS_CONFDIR} -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="-static" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=mipsel-linux-uclibc-gcc \
		DS_AR=mipsel-linux-uclibc-ar \
		DS_LD=mipsel-linux-uclibc-ld \
		DS_RL=mipsel-linux-uclibc-ranlib \
		DS_ST=mipsel-linux-uclibc-strip

######################################################################
#
#	Linux MIPS(LE) crosscompiler for La Fonera 2.0
#
######################################################################
cross-mipsel-fonera2:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-Lopenssl-lib -lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-Iopenssl-include -O2 -DOS_LINUX -DMIPSEL -DUCLIBC -DCS_CONFDIR=${CS_CONFDIR} -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=mips-linux-gcc \
		DS_AR=mips-linux-ar \
		DS_LD=mips-linux-ld \
		DS_RL=mips-linux-ranlib \
		DS_ST=mips-linux-strip

######################################################################
#
#	Linux MIPS(LE) crosscompiler with glibc (DM7025)
#
######################################################################
cross-mipsel-tuxbox-linux-glibc:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DTUXBOX -DMIPSEL -DCS_CONFDIR='\"/var/tuxbox/config\"' -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=mipsel-linux-glibc-gcc \
		DS_AR=mipsel-linux-glibc-ar \
		DS_LD=mipsel-linux-glibc-ld \
		DS_RL=mipsel-linux-glibc-ranlib \
		DS_ST=mipsel-linux-glibc-strip

cross-mipsel-tuxbox-linux:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lcrypto -lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_LINUX -DTUXBOX -DMIPSEL -DCS_CONFDIR='\"/var/tuxbox/config\"' -static-libgcc -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=mipsel-linux-gcc \
		DS_AR=mipsel-linux-ar \
		DS_LD=mipsel-linux-ld \
		DS_RL=mipsel-linux-ranlib \
		DS_ST=mipsel-linux-strip

######################################################################
#
#	HP/UX 10.20 native
#
######################################################################
hppa1.1-hp-hpux10.20:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_HPUX -DOS_HPUX10 -D_XOPEN_SOURCE_EXTENDED -DCS_CONFDIR=${CS_CONFDIR} -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=gcc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip

######################################################################
#
#	OSF5.1 native
#
######################################################################
alpha-dec-osf5.1:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP=$(subst cross-,,$@) \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-O2 -DOS_OSF -DOS_OSF5 -DCS_CONFDIR=${CS_CONFDIR} -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		XDS_CFLAGS="-I/usr/include -c" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_CC=cc \
		DS_AR=ar \
		DS_LD=ld \
		DS_RL=ranlib \
		DS_ST=strip

######################################################################
#
#	ARM crosscompiler (big-endian)
#
######################################################################
cross-arm-nslu2-linux:
	@-$(MAKE) --no-print-directory \
		-f Maketype TYP="$(subst cross-,,$@)" \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-DOS_LINUX -O2 -DARM -DALIGNMENT -DCS_CONFDIR=${CS_CONFDIR} -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_AWK="awk" \
		DS_CC="armv5b-softfloat-linux-gcc" \
		DS_AR="armv5b-softfloat-linux-ar" \
		DS_LD="armv5b-softfloat-linux-ld" \
		DS_RL="armv5b-softfloat-linux-ranlib" \
		DS_ST="armv5b-softfloat-linux-strip"

######################################################################
#
#	ARM crosscompiler (big-endian)
#
######################################################################
cross-armBE-unkown-linux:
	-$(MAKE) --no-print-directory \
		-f Maketype TYP="$(subst cross-,,$@)" \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-DOS_LINUX -O2 -DARM -DALIGNMENT -DCS_CONFDIR=${CS_CONFDIR} -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_AWK="awk" \
		DS_CC="arm-linux-gcc -mbig-endian" \
		DS_AR="arm-linux-ar" \
		DS_LD="arm-linux-ld -EB" \
		DS_RL="arm-linux-ranlib" \
		DS_ST="arm-linux-strip"

######################################################################
#
#	ARM crosscompiler (little-endian)
#
######################################################################
cross-armLE-unkown-linux:
	-$(MAKE) --no-print-directory \
		-f Maketype TYP="$(subst cross-,,$@)" \
		OS_LIBS="-lm" \
		OS_CULI="-lncurses" \
		OS_PTLI="-lpthread" \
		DS_OPTS="-DOS_LINUX -O2 -DARM -DALIGNMENT -DCS_CONFDIR=${CS_CONFDIR}  -D'CS_SVN_VERSION="\"$(SVN_REV)\""'" \
		DS_CFLAGS="-c" \
		DS_LDFLAGS="" \
		DS_ARFLAGS="-rvsl" \
		DS_AWK="awk" \
		DS_CC="arm-linux-gcc -mlittle-endian" \
		DS_AR="arm-linux-ar" \
		DS_LD="arm-linux-ld -EL" \
		DS_RL="arm-linux-ranlib" \
		DS_ST="arm-linux-strip"
