SHELL = /bin/sh

.SUFFIXES:
.SUFFIXES: .o .c .a
.NOTPARALLEL: all
.PHONY: all prepare build-programs help README.build simple default debug config menuconfig allyesconfig allnoconfig defconfig clean distclean

# Include config.mak which contains variables for all enabled modules
# These variables will be used to select only needed files for compilation
-include config.mak

VER     := $(shell ./config.sh --oscam-version)
SVN_REV := $(shell ./config.sh --oscam-revision)

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

# Find OSX SDK
ifeq ($(uname_S),Darwin)
# Setting OSX_VER allows you to choose prefered version if you have
# two SDKs installed. For example if you have 10.6 and 10.5 installed
# you can choose 10.5 by using 'make USE_PCSC=1 OSX_VER=10.5'
# './config.sh --detect-osx-sdk-version' returns the newest SDK if
# SDK_VER is not set.
OSX_SDK := $(shell ./config.sh --detect-osx-sdk-version $(OSX_VER))
override CONFIG_HAVE_DVBAPI:=
endif

ifeq "$(shell ./config.sh --enabled WITH_SSL)" "Y"
	override USE_SSL=1
	override USE_LIBCRYPTO=1
endif
ifdef USE_SSL
	override USE_LIBCRYPTO=1
endif

CONF_DIR = /usr/local/etc

LIB_PTHREAD = -lpthread
LIB_DL = -ldl
ifeq ($(uname_S),FreeBSD)
LIB_DL :=
endif

override STD_LIBS := $(LIB_PTHREAD) $(LIB_DL)
override STD_DEFS := -D'CS_SVN_VERSION="$(SVN_REV)"'
override STD_DEFS += -D'CS_CONFDIR="$(CONF_DIR)"'

# Compiler warnings
CC_WARN = -W -Wall -fno-strict-aliasing -Wredundant-decls -Wstrict-prototypes -Wold-style-definition

# Compiler optimizations
ifndef DEBUG
CC_OPTS = -O2 -ffunction-sections -fdata-sections
else
CC_OPTS = -O0 -ggdb
endif

CC = $(CROSS_DIR)$(CROSS)gcc
AR = $(CROSS_DIR)$(CROSS)ar
STRIP = $(CROSS_DIR)$(CROSS)strip
RANLIB = $(CROSS_DIR)$(CROSS)ranlib

ARFLAGS = -rcsl
LDFLAGS = -Wl,--gc-sections

# The linker for powerpc have bug that prevents --gc-sections from working
# Check for the linker version and if it matches disable --gc-sections
# For more information about the bug see:
#   http://cygwin.com/ml/binutils/2005-01/msg00103.html
LINKER_VER := $(shell $(CC) -Wl,--version 2>&1 | head -1 | cut -d' ' -f5)
# dm500 toolchain
ifeq "$(LINKER_VER)" "20040727"
LDFLAGS :=
endif
# dm600/7000/7020 toolchain
ifeq "$(LINKER_VER)" "20041121"
LDFLAGS :=
endif
# The OS X linker do not support --gc-sections
ifeq ($(uname_S),Darwin)
LDFLAGS :=
endif

# The compiler knows for what target it compiles, so use this information
TARGET := $(shell $(CC) -dumpmachine 2>/dev/null)

# Process USE_ variables
DEFAULT_STAPI_FLAGS = -DWITH_STAPI
DEFAULT_STAPI_LIB = -L./stapi -loscam_stapi
ifdef USE_STAPI
STAPI_FLAGS = $(DEFAULT_STAPI_FLAGS)
STAPI_CFLAGS = $(DEFAULT_STAPI_FLAGS)
STAPI_LDFLAGS = $(DEFAULT_STAPI_FLAGS)
STAPI_LIB = $(DEFAULT_STAPI_LIB)
override PLUS_TARGET := $(PLUS_TARGET)-stapi
CONFIG_WITH_STAPI=y
endif

DEFAULT_COOLAPI_FLAGS = -DWITH_COOLAPI
DEFAULT_COOLAPI_LIB = -lnxp -lrt
ifdef USE_COOLAPI
COOLAPI_FLAGS = $(DEFAULT_COOLAPI_FLAGS)
COOLAPI_CFLAGS = $(DEFAULT_COOLAPI_FLAGS)
COOLAPI_LDFLAGS = $(DEFAULT_COOLAPI_FLAGS)
COOLAPI_LIB = $(DEFAULT_COOLAPI_LIB)
override PLUS_TARGET := $(PLUS_TARGET)-coolapi
CONFIG_WITH_COOLAPI=y
endif

DEFAULT_AZBOX_FLAGS = -DWITH_AZBOX
DEFAULT_AZBOX_LIB = -Lopenxcas -lOpenXCASAPI
ifdef USE_AZBOX
AZBOX_FLAGS = $(DEFAULT_AZBOX_FLAGS)
AZBOX_CFLAGS = $(DEFAULT_AZBOX_FLAGS)
AZBOX_LDFLAGS = $(DEFAULT_AZBOX_FLAGS)
AZBOX_LIB = $(DEFAULT_AZBOX_LIB)
override PLUS_TARGET := $(PLUS_TARGET)-azbox
CONFIG_WITH_AZBOX=y
endif

DEFAULT_LIBCRYPTO_FLAGS = -DWITH_LIBCRYPTO
DEFAULT_LIBCRYPTO_LIB = -lcrypto
ifdef USE_LIBCRYPTO
LIBCRYPTO_FLAGS = $(DEFAULT_LIBCRYPTO_FLAGS)
LIBCRYPTO_CFLAGS = $(DEFAULT_LIBCRYPTO_FLAGS)
LIBCRYPTO_LDFLAGS = $(DEFAULT_LIBCRYPTO_FLAGS)
LIBCRYPTO_LIB = $(DEFAULT_LIBCRYPTO_LIB)
override CONFIG_LIB_BIGNUM:=n
override CONFIG_LIB_SHA1:=n
else
CONFIG_WITHOUT_LIBCRYPTO=y
endif

DEFAULT_SSL_FLAGS = -DWITH_SSL
DEFAULT_SSL_LIB = -lssl
ifdef USE_SSL
SSL_FLAGS = $(DEFAULT_SSL_FLAGS)
SSL_CFLAGS = $(DEFAULT_SSL_FLAGS)
SSL_LDFLAGS = $(DEFAULT_SSL_FLAGS)
SSL_LIB = $(DEFAULT_SSL_LIB)
override PLUS_TARGET := $(PLUS_TARGET)-ssl
endif

DEFAULT_LIBUSB_FLAGS = -DWITH_LIBUSB
ifeq ($(uname_S),Linux)
DEFAULT_LIBUSB_LIB = -lusb-1.0 -lrt
else
DEFAULT_LIBUSB_LIB = -lusb-1.0
endif
ifdef USE_LIBUSB
LIBUSB_FLAGS = $(DEFAULT_LIBUSB_FLAGS)
LIBUSB_CFLAGS = $(DEFAULT_LIBUSB_FLAGS)
LIBUSB_LDFLAGS = $(DEFAULT_LIBUSB_FLAGS)
LIBUSB_LIB = $(DEFAULT_LIBUSB_LIB)
override PLUS_TARGET := $(PLUS_TARGET)-libusb
CONFIG_WITH_LIBUSB=y
endif

ifeq ($(uname_S),Darwin)
DEFAULT_PCSC_FLAGS = -isysroot $(OSX_SDK) -DWITH_PCSC -I/usr/local/include
DEFAULT_PCSC_LIB = -syslibroot,$(OSX_SDK) -framework IOKit -framework CoreFoundation -framework PCSC -L/usr/local/lib
else
DEFAULT_PCSC_FLAGS = -DWITH_PCSC -I/usr/include/PCSC
DEFAULT_PCSC_LIB = -lpcsclite
endif
ifdef USE_PCSC
PCSC_FLAGS = $(DEFAULT_PCSC_FLAGS)
PCSC_CFLAGS = $(DEFAULT_PCSC_FLAGS)
PCSC_LDFLAGS = $(DEFAULT_PCSC_FLAGS)
PCSC_LIB = $(DEFAULT_PCSC_LIB)
override PLUS_TARGET := $(PLUS_TARGET)-pcsc
CONFIG_WITH_PCSC=y
endif

ifdef DEBUG
override PLUS_TARGET := $(PLUS_TARGET)-debug
endif

# Add PLUS_TARGET and EXTRA_TARGET to TARGET
ifdef NO_PLUS_TARGET
override TARGET := $(TARGET)$(EXTRA_TARGET)
else
override TARGET := $(TARGET)$(PLUS_TARGET)$(EXTRA_TARGET)
endif

# Set USE_ flags
override USE_CFLAGS = $(STAPI_CFLAGS) $(COOLAPI_CFLAGS) $(AZBOX_CFLAGS) $(SSL_CFLAGS) $(LIBCRYPTO_CFLAGS) $(LIBUSB_CFLAGS) $(PCSC_CFLAGS)
override USE_LDFLAGS= $(STAPI_LDFLAGS) $(COOLAPI_LDFLAGS) $(AZBOX_LDFLAGS) $(SSL_LDFLAGS) $(LIBCRYPTO_LDFLAGS) $(LIBUSB_LDFLAGS) $(PCSC_LDFLAGS)
override USE_LIBS   = $(STAPI_LIB) $(COOLAPI_LIB) $(AZBOX_LIB) $(SSL_LIB) $(LIBCRYPTO_LIB) $(LIBUSB_LIB) $(PCSC_LIB)

EXTRA_CFLAGS = $(EXTRA_FLAGS)
EXTRA_LDFLAGS = $(EXTRA_FLAGS)

# Add USE_xxx, EXTRA_xxx and STD_xxx vars
override CC_WARN += $(EXTRA_CC_WARN)
override CC_OPTS += $(EXTRA_CC_OPTS)
override CFLAGS  += $(USE_CFLAGS) $(EXTRA_CFLAGS)
override LDFLAGS += $(USE_LDFLAGS) $(EXTRA_LDFLAGS)
override LIBS    += $(USE_LIBS) $(EXTRA_LIBS) $(STD_LIBS)

override STD_DEFS += -D'CS_TARGET="$(TARGET)"'

# This is a *HACK* to enable config variables based on defines
# given in EXTRA_CFLAGS/EXTRA_LDFLAGS/EXTRA_FLAGS variables.
#
# -DXXXXXX is parsed and CONFIG_XXXXXX=y variable is set.
#
# *NOTE*: This is not the proper way to enable features.
#         Use `make config` or `./config --enable CONFIG_VAR`
conf_enabled := $(subst -D,CONFIG_,$(subst =,,$(subst =1,,$(filter -D%,$(sort $(CFLAGS) $(LDFLAGS))))))
$(foreach conf,$(conf_enabled),$(eval override $(conf)=y))

# Setup quiet build
Q =
SAY = @true
ifndef V
Q = @
NP = --no-print-directory
SAY = @echo
endif

BINDIR := Distribution
LIBDIR := lib

OSCAM_BIN := $(BINDIR)/oscam-$(VER)$(SVN_REV)-$(subst cygwin,cygwin.exe,$(TARGET))
LIST_SMARGO_BIN := $(BINDIR)/list_smargo-$(VER)$(SVN_REV)-$(subst cygwin,cygwin.exe,$(TARGET))

# Build list_smargo-.... only when WITH_LIBUSB build is requested.
ifndef USE_LIBUSB
override LIST_SMARGO_BIN =
endif

GLOBAL_DEP = Makefile

ALGO_LIB = $(LIBDIR)/libminilzo-$(TARGET).a
ALGO_DEP = $(GLOBAL_DEP) algo/minilzo.h
ALGO_OBJ-$(CONFIG_LIB_MINILZO) += $(ALGO_LIB)(algo/minilzo.o)
ALGO_OBJ = $(ALGO_OBJ-y)
ifeq "$(ALGO_OBJ)" ""
ALGO_LIB =
endif

CSCRYPT_LIB = $(LIBDIR)/libcscrypt-$(TARGET).a
CSCRYPT_DEP = $(GLOBAL_DEP) cscrypt/cscrypt.h cscrypt/des.h cscrypt/bn.h
CSCRYPT_OBJ-$(CONFIG_WITHOUT_LIBCRYPTO) += $(CSCRYPT_LIB)(cscrypt/aes.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/bn_add.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/bn_asm.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/bn_ctx.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/bn_div.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/bn_exp.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/bn_lib.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/bn_mul.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/bn_print.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/bn_shift.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/bn_sqr.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/bn_word.o)
CSCRYPT_OBJ-$(CONFIG_LIB_BIGNUM) += $(CSCRYPT_LIB)(cscrypt/mem.o)
CSCRYPT_OBJ-y += $(CSCRYPT_LIB)(cscrypt/crc32.o)
CSCRYPT_OBJ-$(CONFIG_LIB_DES) += $(CSCRYPT_LIB)(cscrypt/des.o)
CSCRYPT_OBJ-$(CONFIG_LIB_IDEA) += $(CSCRYPT_LIB)(cscrypt/i_cbc.o)
CSCRYPT_OBJ-$(CONFIG_LIB_IDEA) += $(CSCRYPT_LIB)(cscrypt/i_ecb.o)
CSCRYPT_OBJ-$(CONFIG_LIB_IDEA) += $(CSCRYPT_LIB)(cscrypt/i_skey.o)
CSCRYPT_OBJ-y += $(CSCRYPT_LIB)(cscrypt/md5.o)
CSCRYPT_OBJ-$(CONFIG_LIB_RC6) += $(CSCRYPT_LIB)(cscrypt/rc6.o)
CSCRYPT_OBJ-$(CONFIG_LIB_SHA1) += $(CSCRYPT_LIB)(cscrypt/sha1.o)
CSCRYPT_OBJ = $(CSCRYPT_OBJ-y)

CSCTAPI_LIB = $(LIBDIR)/libcsctapi-$(TARGET).a
CSCTAPI_DEP = $(GLOBAL_DEP) csctapi/defines.h csctapi/atr.h
CSCTAPI_OBJ-$(CONFIG_WITH_CARDREADER) += $(CSCTAPI_LIB)(csctapi/atr.o)
CSCTAPI_OBJ-$(CONFIG_WITH_CARDREADER) += $(CSCTAPI_LIB)(csctapi/icc_async.o)
CSCTAPI_OBJ-$(CONFIG_WITH_AZBOX) += $(CSCTAPI_LIB)(csctapi/ifd_azbox.o)
CSCTAPI_OBJ-$(CONFIG_WITH_COOLAPI) += $(CSCTAPI_LIB)(csctapi/ifd_cool.o)
CSCTAPI_OBJ-$(CONFIG_WITH_CARDREADER) += $(CSCTAPI_LIB)(csctapi/ifd_mp35.o)
CSCTAPI_OBJ-$(CONFIG_WITH_PCSC) += $(CSCTAPI_LIB)(csctapi/ifd_pcsc.o)
CSCTAPI_OBJ-$(CONFIG_WITH_CARDREADER) += $(CSCTAPI_LIB)(csctapi/ifd_phoenix.o)
CSCTAPI_OBJ-$(CONFIG_WITH_CARDREADER) += $(CSCTAPI_LIB)(csctapi/ifd_sc8in1.o)
CSCTAPI_OBJ-$(CONFIG_WITH_CARDREADER) += $(CSCTAPI_LIB)(csctapi/ifd_sci.o)
CSCTAPI_OBJ-$(CONFIG_WITH_CARDREADER) += $(CSCTAPI_LIB)(csctapi/ifd_smargo.o)
CSCTAPI_OBJ-$(CONFIG_WITH_LIBUSB) += $(CSCTAPI_LIB)(csctapi/ifd_smartreader.o)
CSCTAPI_OBJ-$(CONFIG_WITH_STAPI) += $(CSCTAPI_LIB)(csctapi/ifd_stapi.o)
CSCTAPI_OBJ-$(CONFIG_WITH_CARDREADER) += $(CSCTAPI_LIB)(csctapi/io_serial.o)
CSCTAPI_OBJ-$(CONFIG_WITH_CARDREADER) += $(CSCTAPI_LIB)(csctapi/protocol_t0.o)
CSCTAPI_OBJ-$(CONFIG_WITH_CARDREADER) += $(CSCTAPI_LIB)(csctapi/protocol_t1.o)
CSCTAPI_OBJ-$(CONFIG_WITH_CARDREADER) += $(CSCTAPI_LIB)(csctapi/t1_block.o)
CSCTAPI_OBJ = $(CSCTAPI_OBJ-y)
ifeq "$(CSCTAPI_OBJ)" ""
CSCTAPI_LIB =
endif

OSCAM_LIB = $(LIBDIR)/libcs-$(TARGET).a
OSCAM_DEP = $(GLOBAL_DEP) globals.h oscam-config.h
OSCAM_OBJ-$(CONFIG_CS_ANTICASC) += $(OSCAM_LIB)(module-anticasc.o)
OSCAM_OBJ-$(CONFIG_MODULE_CAMD33) += $(OSCAM_LIB)(module-camd33.o)
OSCAM_OBJ-$(sort $(CONFIG_MODULE_CAMD35) $(CONFIG_MODULE_CAMD35_TCP)) += $(OSCAM_LIB)(module-camd35.o)
OSCAM_OBJ-$(CONFIG_MODULE_CCCAM) += $(OSCAM_LIB)(module-cccam.o)
OSCAM_OBJ-$(CONFIG_MODULE_CCCAM) += $(OSCAM_LIB)(module-cccshare.o)
OSCAM_OBJ-$(CONFIG_MODULE_CONSTCW) += $(OSCAM_LIB)(module-constcw.o)
OSCAM_OBJ-$(CONFIG_CS_CACHEEX) += $(OSCAM_LIB)(module-csp.o)
OSCAM_OBJ-$(CONFIG_WITH_AZBOX) += $(OSCAM_LIB)(module-dvbapi-azbox.o)
OSCAM_OBJ-$(CONFIG_WITH_COOLAPI) += $(OSCAM_LIB)(module-dvbapi-coolapi.o)
OSCAM_OBJ-$(CONFIG_WITH_STAPI) += $(OSCAM_LIB)(module-dvbapi-stapi.o)
OSCAM_OBJ-$(CONFIG_HAVE_DVBAPI) += $(OSCAM_LIB)(module-dvbapi.o)
OSCAM_OBJ-$(CONFIG_MODULE_GBOX) += $(OSCAM_LIB)(module-gbox.o)
OSCAM_OBJ-$(CONFIG_LCDSUPPORT) += $(OSCAM_LIB)(module-lcd.o)
OSCAM_OBJ-$(CONFIG_MODULE_MONITOR) += $(OSCAM_LIB)(module-monitor.o)
OSCAM_OBJ-$(CONFIG_MODULE_NEWCAMD) += $(OSCAM_LIB)(module-newcamd.o)
OSCAM_OBJ-$(CONFIG_MODULE_PANDORA) += $(OSCAM_LIB)(module-pandora.o)
OSCAM_OBJ-$(CONFIG_MODULE_RADEGAST) += $(OSCAM_LIB)(module-radegast.o)
OSCAM_OBJ-$(CONFIG_MODULE_SERIAL) += $(OSCAM_LIB)(module-serial.o)
OSCAM_OBJ-$(CONFIG_WITH_LB) += $(OSCAM_LIB)(module-stat.o)
OSCAM_OBJ-$(CONFIG_WEBIF) += $(OSCAM_LIB)(module-webif.o)
OSCAM_OBJ-$(CONFIG_WEBIF) += $(OSCAM_LIB)(module-webif-lib.o)
OSCAM_OBJ-$(CONFIG_WEBIF) += $(OSCAM_LIB)(module-webif-pages.o)
OSCAM_OBJ-$(CONFIG_WITH_CARDREADER) += $(OSCAM_LIB)(reader-common.o)
OSCAM_OBJ-$(CONFIG_READER_BULCRYPT) += $(OSCAM_LIB)(reader-bulcrypt.o)
OSCAM_OBJ-$(CONFIG_READER_CONAX) += $(OSCAM_LIB)(reader-conax.o)
OSCAM_OBJ-$(CONFIG_READER_CRYPTOWORKS) += $(OSCAM_LIB)(reader-cryptoworks.o)
OSCAM_OBJ-$(CONFIG_READER_DRE) += $(OSCAM_LIB)(reader-dre.o)
OSCAM_OBJ-$(CONFIG_READER_IRDETO) += $(OSCAM_LIB)(reader-irdeto.o)
OSCAM_OBJ-$(CONFIG_READER_NAGRA) += $(OSCAM_LIB)(reader-nagra.o)
OSCAM_OBJ-$(CONFIG_READER_SECA) += $(OSCAM_LIB)(reader-seca.o)
OSCAM_OBJ-$(CONFIG_READER_TONGFANG) += $(OSCAM_LIB)(reader-tongfang.o)
OSCAM_OBJ-$(CONFIG_READER_VIACCESS) += $(OSCAM_LIB)(reader-viaccess.o)
OSCAM_OBJ-$(CONFIG_READER_VIDEOGUARD) += $(OSCAM_LIB)(reader-videoguard-common.o)
OSCAM_OBJ-$(CONFIG_READER_VIDEOGUARD) += $(OSCAM_LIB)(reader-videoguard1.o)
OSCAM_OBJ-$(CONFIG_READER_VIDEOGUARD) += $(OSCAM_LIB)(reader-videoguard12.o)
OSCAM_OBJ-$(CONFIG_READER_VIDEOGUARD) += $(OSCAM_LIB)(reader-videoguard2.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-chk.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-conf.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-conf-chk.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-conf-mk.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-config-account.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-config-global.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-config-reader.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-config.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-garbage.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-log.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-llist.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-reader.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam-simples.o)
OSCAM_OBJ-y += $(OSCAM_LIB)(oscam.o)
OSCAM_OBJ = $(OSCAM_OBJ-y)

# The default build target rebuilds the config.mak if needed and then
# starts the compilation.
all:
	$(shell ./config.sh --make-config.mak)
	@$(MAKE) --no-print-directory build-programs

build-programs: prepare $(OSCAM_BIN) $(LIST_SMARGO_BIN)

prepare:
	@-test -d "$(LIBDIR)" || mkdir "$(LIBDIR)"
	@-printf "\
+-------------------------------------------------------------------------------\n\
| OSCam ver: $(VER) rev: $(SVN_REV) target: $(TARGET)\n\
| Tools:\n\
|  CROSS    = $(CROSS_DIR)$(CROSS)\n\
|  CC       = $(CC)\n\
|  AR       = $(AR)\n\
|  STRIP    = $(STRIP)\n\
|  RANLIB   = $(RANLIB)\n\
| Settings:\n\
|  CONF_DIR = $(CONF_DIR)\n\
|  CC_OPTS  = $(strip $(CC_OPTS))\n\
|  CC_WARN  = $(strip $(CC_WARN))\n\
|  CFLAGS   = $(strip $(CFLAGS))\n\
|  LDFLAGS  = $(strip $(LDFLAGS))\n\
|  LIBS     = $(strip $(LIBS))\n\
| Config:\n\
|  Addons   : $(shell ./config.sh --show-enabled addons)\n\
|  Protocols: $(shell ./config.sh --show-enabled protocols | sed -e 's|MODULE_||g')\n\
|  Readers  : $(shell ./config.sh --show-enabled readers | sed -e 's|READER_||g')\n\
|  Compiler : $(shell $(CC) --version 2>/dev/null | head -n 1)\n\
|  Linker   : $(shell $(CC) -Wl,-v 2>&1 | head -n 1)\n\
|  Binary   : $(OSCAM_BIN)\n\
+-------------------------------------------------------------------------------\n"

$(ALGO_OBJ): $(ALGO_DEP)
$(ALGO_LIB): $(ALGO_OBJ)
	-@$(RANLIB) $@

$(CSCRYPT_OBJ): $(CSCRYPT_DEP)
$(CSCRYPT_LIB): $(CSCRYPT_OBJ)
	-@$(RANLIB) $@

$(CSCTAPI_OBJ): $(CSCTAPI_DEP)
$(CSCTAPI_LIB): $(CSCTAPI_OBJ)
	-@$(RANLIB) $@

$(OSCAM_OBJ): $(OSCAM_DEP)
$(OSCAM_LIB): $(OSCAM_OBJ)
	-@$(RANLIB) $@

$(OSCAM_BIN): $(ALGO_LIB) $(CSCRYPT_LIB) $(CSCTAPI_LIB) $(OSCAM_LIB)
	$(SAY) "LINK	$@"
	$(Q)$(CC) $(LDFLAGS) $(OSCAM_LIB) $(ALGO_LIB) $(CSCRYPT_LIB) $(CSCTAPI_LIB) $(LIBS) -o $@
ifndef DEBUG
	$(SAY) "STRIP	$@"
	$(Q)$(STRIP) $@
endif

$(LIST_SMARGO_BIN): utils/list_smargo.c
	$(SAY) "LINK	$@"
	$(Q)$(CC) $(STD_DEFS) $(LDFLAGS) utils/list_smargo.c $(LIBS) -o $@
ifndef DEBUG
	$(SAY) "STRIP	$@"
	$(Q)$(STRIP) $@
endif

.c.a:
	$(SAY) "CC	$<"
	$(Q)$(CC) $(STD_DEFS) $(CC_OPTS) $(CC_WARN) $(CFLAGS) -c $< -o $(subst .c,.o,$<)
	@$(AR) $(ARFLAGS) $@ $*.o
	-@rm -f $*.o

config:
	$(SHELL) ./config.sh --gui

menuconfig: config

allyesconfig:
	@echo "Enabling all config options."
	@-$(SHELL) ./config.sh --enable all

allnoconfig:
	@echo "Disabling all config options."
	@-$(SHELL) ./config.sh --disable all

defconfig:
	@echo "Restoring default config."
	@-$(SHELL) ./config.sh --restore

clean:
	@-rm -rfv $(LIBDIR)/*.a

distclean: clean
	@-rm -rfv $(BINDIR)/oscam-$(VER)* $(BINDIR)/list_smargo-* config.mak

README.build:
	@echo "Extracting 'make help' into $@ file."
	@-printf "\
** This file is generated from 'make help' output, do not edit it. **\n\
\n\
" > $@
	@-make --no-print-directory help >> $@
	@echo "Done."

help:
	@-printf "\
OSCam build system documentation\n\
================================\n\
\n\
 Build variables:\n\
   The build variables are set on the make command line and control the build\n\
   process. Setting the variables lets you enable additional features, request\n\
   extra libraries and more. Currently recognized build variables are:\n\
\n\
   CROSS=prefix   - Set tools prefix. This variable is used when OScam is being\n\
                    cross compiled. For example if you want to cross compile\n\
                    for SH4 architecture you can run: 'make CROSS=sh4-linux-'\n\
                    If you don't have the directory where cross compilers are\n\
                    in your PATH you can run:\n\
                    'make CROSS=/opt/STM/STLinux-2.3/devkit/sh4/bin/sh4-linux-'\n\
\n\
   CROSS_DIR=dir  - Set tools directory. This variable is added in front of\n\
                    CROSS variable. CROSS_DIR is useful if you want to use\n\
                    predefined targets that are setting CROSS, but you don't have\n\
                    the cross compilers in your PATH. For example:\n\
                    'make sh4 CROSS_DIR=/opt/STM/STLinux-2.3/devkit/sh4/bin/'\n\
                    'make dm500 CROSS_DIR=/opt/cross/dm500/cdk/bin/'\n\
\n\
   CONF_DIR=/dir  - Set OSCam config directory. For example to change config\n\
                    directory to /etc run: 'make CONF_DIR=/etc'\n\
                    The default config directory is: '$(CONF_DIR)'\n\
\n\
   DEBUG=1        - Compile OScam with debug information.\n\
                    Using DEBUG=1 adds '-debug' to PLUS_TARGET.\n\
\n\
   CC_OPTS=text   - This variable holds compiler optimization parameters.\n\
                    Default CC_OPTS value is:\n\
                    '$(CC_OPTS)'\n\
                    To add text to this variable set EXTRA_CC_OPTS=text.\n\
\n\
   CC_WARN=text   - This variable holds compiler warning parameters.\n\
                    Default CC_WARN value is:\n\
                    '$(CC_WARN)'\n\
                    To add text to this variable set EXTRA_CC_WARN=text.\n\
\n\
   V=1            - Request build process to print verbose messages. By\n\
                    default the only messages that are shown are simple info\n\
                    what is being compiled. To request verbose build run:\n\
                    'make V=1'\n\
\n\
 Extra build variables:\n\
   These variables add text to build variables. They are useful if you want\n\
   to add additional options to already set variables without overwriting them\n\
   Currently defined EXTRA_xxx variables are:\n\
\n\
   EXTRA_CC_OPTS  - Add text to CC_OPTS.\n\
                    Example: 'make EXTRA_CC_OPTS=-Os'\n\
\n\
   EXTRA_CC_WARN  - Add text to CC_WARN.\n\
                    Example: 'make EXTRA_CC_WARN=-Wshadow'\n\
\n\
   EXTRA_TARGET   - Add text to TARGET.\n\
                    Example: 'make EXTRA_TARGET=-private'\n\
\n\
   EXTRA_CFLAGS   - Add text to CFLAGS (affects compilation).\n\
                    Example: 'make EXTRA_CFLAGS=\"-DBLAH=1 -I/opt/local\"'\n\
\n\
   EXTRA_LDLAGS   - Add text to LDLAGS (affects linking).\n\
                    Example: 'make EXTRA_LDLAGS=-Llibdir'\n\
\n\
   EXTRA_FLAGS    - Add text to both EXTRA_CFLAGS and EXTRA_LDFLAGS.\n\
                    Example: 'make EXTRA_FLAGS=-DWEBIF=1'\n\
\n\
   EXTRA_LIBS     - Add text to LIBS (affects linking).\n\
                    Example: 'make EXTRA_LIBS=\"-L./stapi -loscam_stapi\"'\n\
\n\
 Use flags:\n\
   Use flags are used to request additional libraries or features to be used\n\
   by OSCam. Currently defined USE_xxx flags are:\n\
\n\
   USE_LIBUSB=1    - Request linking with libusb. The variables that control\n\
                     USE_LIBUSB=1 build are:\n\
                         LIBUSB_FLAGS='$(DEFAULT_LIBUSB_FLAGS)'\n\
                         LIBUSB_CFLAGS='$(DEFAULT_LIBUSB_FLAGS)'\n\
                         LIBUSB_LDFLAGS='$(DEFAULT_LIBUSB_FLAGS)'\n\
                         LIBUSB_LIB='$(DEFAULT_LIBUSB_LIB)'\n\
                     Using USE_LIBUSB=1 adds to '-libusb' to PLUS_TARGET.\n\
                     To build with static libusb, set the variable LIBUSB_LIB\n\
                     to contain full path of libusb library. For example:\n\
                      make USR_LIBUSB=1 LIBUSB_LIB=/usr/lib/libusb-1.0.a\n\
\n\
   USE_PCSC=1      - Request linking with PCSC. The variables that control\n\
                     USE_PCSC=1 build are:\n\
                         PCSC_FLAGS='$(DEFAULT_PCSC_FLAGS)'\n\
                         PCSC_CFLAGS='$(DEFAULT_PCSC_FLAGS)'\n\
                         PCSC_LDFLAGS='$(DEFAULT_PCSC_FLAGS)'\n\
                         PCSC_LIB='$(DEFAULT_PCSC_LIB)'\n\
                     Using USE_PCSC=1 adds to '-pcsc' to PLUS_TARGET.\n\
                     To build with static PCSC, set the variable PCSC_LIB\n\
                     to contain full path of PCSC library. For example:\n\
                      make USE_PCSC=1 PCSC_LIB=/usr/local/lib/libpcsclite.a\n\
\n\
   USE_STAPI=1    - Request linking with STAPI. The variables that control\n\
                     USE_STAPI=1 build are:\n\
                         STAPI_FLAGS='$(DEFAULT_STAPI_FLAGS)'\n\
                         STAPI_CFLAGS='$(DEFAULT_STAPI_FLAGS)'\n\
                         STAPI_LDFLAGS='$(DEFAULT_STAPI_FLAGS)'\n\
                         STAPI_LIB='$(DEFAULT_STAPI_LIB)'\n\
                     Using USE_STAPI=1 adds to '-stapi' to PLUS_TARGET.\n\
                     In order for USE_STAPI to work you have to create stapi\n\
                     directory and put liboscam_stapi.a file in it.\n\
\n\
   USE_COOLAPI=1  - Request support for Coolstream API (libnxp) aka NeutrinoHD\n\
                    box. The variables that control the build are:\n\
                         COOLAPI_FLAGS='$(DEFAULT_COOLAPI_FLAGS)'\n\
                         COOLAPI_CFLAGS='$(DEFAULT_COOLAPI_FLAGS)'\n\
                         COOLAPI_LDFLAGS='$(DEFAULT_COOLAPI_FLAGS)'\n\
                         COOLAPI_LIB='$(DEFAULT_COOLAPI_LIB)'\n\
                     Using USE_COOLAPI=1 adds to '-coolapi' to PLUS_TARGET.\n\
                     In order for USE_COOLAPI to work you have to have libnxp.so\n\
                     library in your cross compilation toolchain.\n\
\n\
   USE_AZBOX=1    - Request support for AZBOX (openxcas)\n\
                    box. The variables that control the build are:\n\
                         AZBOX_FLAGS='$(DEFAULT_AZBOX_FLAGS)'\n\
                         AZBOX_CFLAGS='$(DEFAULT_AZBOX_FLAGS)'\n\
                         AZBOX_LDFLAGS='$(DEFAULT_AZBOX_FLAGS)'\n\
                         AZBOX_LIB='$(DEFAULT_AZBOX_LIB)'\n\
                     Using USE_AZBOX=1 adds to '-azbox' to PLUS_TARGET.\n\
                     The openxcas/libOpenXCASAPI.a library shipped with OSCam\n\
                     is compiled for MIPSEL.\n\
\n\
   USE_LIBCRYPTO=1 - Request linking with libcrypto instead of using OSCam\n\
                     internal crypto functions. USE_LIBCRYPTO is automatically\n\
                     enabled if the build is configured with SSL support. The\n\
                     variables that control USE_LIBCRYPTO=1 build are:\n\
                         LIBCRYPTO_FLAGS='$(DEFAULT_LIBCRYPTO_FLAGS)'\n\
                         LIBCRYPTO_CFLAGS='$(DEFAULT_LIBCRYPTO_FLAGS)'\n\
                         LIBCRYPTO_LDFLAGS='$(DEFAULT_LIBCRYPTO_FLAGS)'\n\
                         LIBCRYPTO_LIB='$(DEFAULT_LIBCRYPTO_LIB)'\n\
\n\
   USE_SSL=1       - Request linking with libssl. USE_SSL is automatically\n\
                     enabled if the build is configured with SSL support. The\n\
                     variables that control USE_SSL=1 build are:\n\
                         SSL_FLAGS='$(DEFAULT_SSL_FLAGS)'\n\
                         SSL_CFLAGS='$(DEFAULT_SSL_FLAGS)'\n\
                         SSL_LDFLAGS='$(DEFAULT_SSL_FLAGS)'\n\
                         SSL_LIB='$(DEFAULT_SSL_LIB)'\n\
                     Using USE_SSL=1 adds to '-ssl' to PLUS_TARGET.\n\
\n\
 Automatically intialized variables:\n\
\n\
   TARGET=text     - This variable is auto detected by using the compiler's\n\
                    -dumpmachine output. To see the target on your machine run:\n\
                     'gcc -dumpmachine'\n\
\n\
   PLUS_TARGET     - This variable is added to TARGET and it is set depending\n\
                     on the chosen USE_xxx (or DEBUG) flags. To disable adding\n\
                     PLUS_TARGET to TARGET, set NO_PLUS_TARGET=1\n\
\n\
   BINDIR          - The directory where final oscam binary would be put. The\n\
                     default is: $(BINDIR)\n\
\n\
   OSCAM_BIN=text  - This variable controls how the oscam binary will be named.\n\
                     Default OSCAM_BIN value is:\n\
                      'BINDIR/oscam-VERSVN_REV-TARGET'\n\
                     Once the variables (BINDIR, VER, SVN_REV and TARGET) are\n\
                     replaced, the resulting filename can look like this:\n\
                      'Distribution/oscam-1.20-unstable_svn7404-i486-slackware-linux-static'\n\
                     For example you can run: 'make OSCAM_BIN=my-oscam'\n\
\n\
 Config targets:\n\
   make config        - Start configuration utility.\n\
   make allyesconfig  - Enable all configuration options.\n\
   make allnoconfig   - Disable all configuration options.\n\
   make defconfig     - Restore default configuration options.\n\
\n\
 Cleaning targets:\n\
   make clean     - Remove '$(LIBDIR)' directory which contains compiled\n\
                    object files.\n\
   make distclean - Executes clean target and also removes binary files\n\
                    located in '$(BINDIR)' directory.\n\
\n\
 Build system files:\n\
   config.sh      - OSCam configuration. Run 'config.sh --help' to see\n\
                    available parameters or 'make config' to start GUI\n\
                    configuratior.\n\
   Makefile       - Main build system file.\n\
   Makefile.extra - Contains predefined targets. You can use this file\n\
                    as example on how to use the build system.\n\
   Makefile.local - This file is included in Makefile and allows creation\n\
                    of local build system targets. See Makefile.extra for\n\
                    examples.\n\
\n\
 Here are some of the interesting predefined targets in Makefile.extra.\n\
 To use them run 'make target ...' where ... can be any extra flag. For\n\
 example if you want to compile OSCam for Dreambox (DM500) but do not\n\
 have the compilers in the path, you can run:\n\
    make dm500 CROSS_DIR=/opt/cross/dm500/cdk/bin/\n\
\n\
 Predefined targets in Makefile.extra:\n\
\n\
    make libusb        - Builds OSCam with libusb support\n\
    make pcsc          - Builds OSCam with PCSC support\n\
    make pcsc-libusb   - Builds OSCam with PCSC and libusb support\n\
    make dm500         - Builds OSCam for Dreambox (DM500)\n\
    make sh4           - Builds OSCam for SH4 boxes\n\
    make azbox         - Builds OSCam for AZBox STBs\n\
    make coolstream    - Builds OSCam for Coolstream\n\
    make dockstar      - Builds OSCam for Dockstar\n\
    make opensolaris   - Builds OSCam for OpenSolaris\n\
\n\
 Predefined targets for static builds:\n\
    make static        - Builds OSCam statically\n\
    make static-libusb - Builds OSCam with libusb linked statically\n\
    make static-libcrypto - Builds OSCam with libcrypto linked statically\n\
    make static-ssl    - Builds OSCam with SSL support linked statically\n\
\n\
 Examples:\n\
   Build OSCam with debugging information:\n\
     make DEBUG=1\n\n\
   Build OSCam for SH4 (the compilers are in the path):\n\
     make CROSS=sh4-linux-\n\n\
   Build OSCam for SH4 (the compilers are in not in the path):\n\
     make sh4 CROSS_DIR=/opt/STM/STLinux-2.3/devkit/sh4/bin/\n\
     make CROSS_DIR=/opt/STM/STLinux-2.3/devkit/sh4/bin/ CROSS=sh4-linux-\n\
     make CROSS=/opt/STM/STLinux-2.3/devkit/sh4/bin/sh4-linux-\n\n\
   Build OSCam for SH4 with STAPI:\n\
     make CROSS=sh4-linux- USE_STAPI=1\n\n\
   Build OSCam for SH4 with STAPI and changed configuration directory:\n\
     make CROSS=sh4-linux- USE_STAPI=1 CONF_DIR=/var/tuxbox/config\n\n\
   Build OSCam for ARM with COOLAPI (coolstream aka NeutrinoHD):\n\
     make CROSS=arm-cx2450x-linux-gnueabi- USE_COOLAPI=1\n\n\
   Build OSCam for MIPSEL with AZBOX support:\n\
     make CROSS=mipsel-linux-uclibc- USE_AZBOX=1\n\n\
   Build OSCam with libusb and PCSC:\n\
     make USE_LIBUSB=1 USE_PCSC=1\n\n\
   Build OSCam with static libusb:\n\
     make USE_LIBUSB=1 LIBUSB_LIB=\"/usr/lib/libusb-1.0.a\"\n\n\
   Build OSCam with static libcrypto:\n\
     make USE_LIBCRYPTO=1 LIBCRYPTO_LIB=\"/usr/lib/libcrypto.a\"\n\n\
   Build OSCam with static libssl and libcrypto:\n\
     make USE_SSL=1 SSL_LIB=\"/usr/lib/libssl.a\" LIBCRYPTO_LIB=\"/usr/lib/libcrypto.a\"\n\n\
   Build with verbose messages and size optimizations:\n\
     make V=1 CC_OPTS=-Os\n\n\
   Build and set oscam file name:\n\
     make OSCAM_BIN=oscam\n\n\
   Build and set oscam file name depending on revision:\n\
     make OSCAM_BIN=oscam-\`./config.sh -r\`\n\n\
"

simple: all
default: all

debug:
	$(MAKE) --no-print-directory \
		DEBUG=1 \
		$(MAKEFLAGS)

-include Makefile.extra
-include Makefile.local
