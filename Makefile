SHELL = /bin/sh

.SUFFIXES:
.SUFFIXES: .o .c .a
.NOTPARALLEL: all
.PHONY: help

VER     := $(shell ./config.sh --oscam-version)
SVN_REV := $(shell ./config.sh --oscam-revision)

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

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

override STD_LIBS := $(LIB_PTHREAD) $(LIB_DL)
override STD_DEFS := -D'CS_SVN_VERSION="$(SVN_REV)"'
override STD_DEFS += -D'CS_CONFDIR="$(CONF_DIR)"'

# Compiler warnings
CC_WARN = -W -Wall -fno-strict-aliasing -Wredundant-decls -Wstrict-prototypes -Wold-style-definition

# Compiler optimizations
ifndef DEBUG
CC_OPTS = -O2
else
CC_OPTS = -O0 -ggdb
endif

CC = $(CROSS_DIR)$(CROSS)gcc
AR = $(CROSS_DIR)$(CROSS)ar
STRIP = $(CROSS_DIR)$(CROSS)strip
RANLIB = $(CROSS_DIR)$(CROSS)ranlib

ARFLAGS = -rcsl

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
endif

DEFAULT_COOLAPI_FLAGS = -DWITH_COOLAPI
DEFAULT_COOLAPI_LIB = -lnxp -lrt
ifdef USE_COOLAPI
COOLAPI_FLAGS = $(DEFAULT_COOLAPI_FLAGS)
COOLAPI_CFLAGS = $(DEFAULT_COOLAPI_FLAGS)
COOLAPI_LDFLAGS = $(DEFAULT_COOLAPI_FLAGS)
COOLAPI_LIB = $(DEFAULT_COOLAPI_LIB)
override PLUS_TARGET := $(PLUS_TARGET)-coolapi
endif

DEFAULT_AZBOX_FLAGS = -DWITH_AZBOX
DEFAULT_AZBOX_LIB = -Lopenxcas -lOpenXCASAPI
ifdef USE_AZBOX
AZBOX_FLAGS = $(DEFAULT_AZBOX_FLAGS)
AZBOX_CFLAGS = $(DEFAULT_AZBOX_FLAGS)
AZBOX_LDFLAGS = $(DEFAULT_AZBOX_FLAGS)
AZBOX_LIB = $(DEFAULT_AZBOX_LIB)
override PLUS_TARGET := $(PLUS_TARGET)-azbox
endif

DEFAULT_LIBCRYPTO_FLAGS = -DWITH_LIBCRYPTO
DEFAULT_LIBCRYPTO_LIB = -lcrypto
ifdef USE_LIBCRYPTO
LIBCRYPTO_FLAGS = $(DEFAULT_LIBCRYPTO_FLAGS)
LIBCRYPTO_CFLAGS = $(DEFAULT_LIBCRYPTO_FLAGS)
LIBCRYPTO_LDFLAGS = $(DEFAULT_LIBCRYPTO_FLAGS)
LIBCRYPTO_LIB = $(DEFAULT_LIBCRYPTO_LIB)
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

DEFAULT_LIBUSB_FLAGS = -DLIBUSB
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
endif

DEFAULT_PCSC_FLAGS = -DHAVE_PCSC=1 -I/usr/include/PCSC
DEFAULT_PCSC_LIB = -lpcsclite
ifdef USE_PCSC
PCSC_FLAGS = $(DEFAULT_PCSC_FLAGS)
PCSC_CFLAGS = $(DEFAULT_PCSC_FLAGS)
PCSC_LDFLAGS = $(DEFAULT_PCSC_FLAGS)
PCSC_LIB = $(DEFAULT_PCSC_LIB)
override PLUS_TARGET := $(PLUS_TARGET)-pcsc
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

# Setup quiet build
Q =
SAY = @true
ifndef V
Q = @
NP = --no-print-directory
SAY = @echo
endif

OSCAM_BIN := Distribution/oscam-$(VER)$(SVN_REV)-$(subst cygwin,cygwin.exe,$(TARGET))
LIST_SMARGO_BIN := Distribution/list_smargo-$(VER)$(SVN_REV)-$(subst cygwin,cygwin.exe,$(TARGET))

LIBDIR = lib

GLOBAL_DEP = Makefile

ALGO_LIB = $(LIBDIR)/libminilzo-$(TARGET).a
ALGO_DEP = $(GLOBAL_DEP) algo/minilzo.h
ALGO_OBJ = \
	$(ALGO_LIB)(algo/minilzo.o)

CSCRYPT_LIB = $(LIBDIR)/libcscrypt-$(TARGET).a
CSCRYPT_DEP = $(GLOBAL_DEP) cscrypt/cscrypt.h cscrypt/des.h cscrypt/bn.h
CSCRYPT_OBJ = \
	$(CSCRYPT_LIB)(cscrypt/aes.o) \
	$(CSCRYPT_LIB)(cscrypt/bn_add.o) \
	$(CSCRYPT_LIB)(cscrypt/bn_asm.o) \
	$(CSCRYPT_LIB)(cscrypt/bn_ctx.o) \
	$(CSCRYPT_LIB)(cscrypt/bn_div.o) \
	$(CSCRYPT_LIB)(cscrypt/bn_exp.o) \
	$(CSCRYPT_LIB)(cscrypt/bn_lib.o) \
	$(CSCRYPT_LIB)(cscrypt/bn_mul.o) \
	$(CSCRYPT_LIB)(cscrypt/bn_print.o) \
	$(CSCRYPT_LIB)(cscrypt/bn_shift.o) \
	$(CSCRYPT_LIB)(cscrypt/bn_sqr.o) \
	$(CSCRYPT_LIB)(cscrypt/bn_word.o) \
	$(CSCRYPT_LIB)(cscrypt/crc32.o) \
	$(CSCRYPT_LIB)(cscrypt/des.o) \
	$(CSCRYPT_LIB)(cscrypt/i_cbc.o) \
	$(CSCRYPT_LIB)(cscrypt/i_ecb.o) \
	$(CSCRYPT_LIB)(cscrypt/i_skey.o) \
	$(CSCRYPT_LIB)(cscrypt/md5.o) \
	$(CSCRYPT_LIB)(cscrypt/mem.o) \
	$(CSCRYPT_LIB)(cscrypt/rc6.o) \
	$(CSCRYPT_LIB)(cscrypt/sha1.o)

CSCTAPI_LIB = $(LIBDIR)/libcsctapi-$(TARGET).a
CSCTAPI_DEP = $(GLOBAL_DEP) csctapi/defines.h csctapi/atr.h
CSCTAPI_OBJ = \
	$(CSCTAPI_LIB)(csctapi/atr.o) \
	$(CSCTAPI_LIB)(csctapi/icc_async.o) \
	$(CSCTAPI_LIB)(csctapi/ifd_azbox.o) \
	$(CSCTAPI_LIB)(csctapi/ifd_cool.o) \
	$(CSCTAPI_LIB)(csctapi/ifd_mp35.o) \
	$(CSCTAPI_LIB)(csctapi/ifd_pcsc.o) \
	$(CSCTAPI_LIB)(csctapi/ifd_phoenix.o) \
	$(CSCTAPI_LIB)(csctapi/ifd_sc8in1.o) \
	$(CSCTAPI_LIB)(csctapi/ifd_sci.o) \
	$(CSCTAPI_LIB)(csctapi/ifd_smargo.o) \
	$(CSCTAPI_LIB)(csctapi/ifd_smartreader.o) \
	$(CSCTAPI_LIB)(csctapi/ifd_stapi.o) \
	$(CSCTAPI_LIB)(csctapi/io_serial.o) \
	$(CSCTAPI_LIB)(csctapi/protocol_t0.o) \
	$(CSCTAPI_LIB)(csctapi/protocol_t1.o) \
	$(CSCTAPI_LIB)(csctapi/t1_block.o)

OSCAM_LIB = $(LIBDIR)/libcs-$(TARGET).a
OSCAM_DEP = $(GLOBAL_DEP) globals.h oscam-config.h
OSCAM_OBJ = \
	$(OSCAM_LIB)(module-camd33.o) \
	$(OSCAM_LIB)(module-camd35.o) \
	$(OSCAM_LIB)(module-cccam.o) \
	$(OSCAM_LIB)(module-cccshare.o) \
	$(OSCAM_LIB)(module-constcw.o) \
	$(OSCAM_LIB)(module-csp.o) \
	$(OSCAM_LIB)(module-datastruct-llist.o) \
	$(OSCAM_LIB)(module-dvbapi-azbox.o)\
	$(OSCAM_LIB)(module-dvbapi-coolapi.o)\
	$(OSCAM_LIB)(module-dvbapi-stapi.o) \
	$(OSCAM_LIB)(module-dvbapi.o) \
	$(OSCAM_LIB)(module-gbox.o) \
	$(OSCAM_LIB)(module-lcd.o) \
	$(OSCAM_LIB)(module-monitor.o) \
	$(OSCAM_LIB)(module-newcamd.o) \
	$(OSCAM_LIB)(module-pandora.o) \
	$(OSCAM_LIB)(module-pandora.o) \
	$(OSCAM_LIB)(module-radegast.o) \
	$(OSCAM_LIB)(module-serial.o) \
	$(OSCAM_LIB)(module-stat.o) \
	$(OSCAM_LIB)(oscam-ac.o) \
	$(OSCAM_LIB)(oscam-chk.o) \
	$(OSCAM_LIB)(oscam-config.o) \
	$(OSCAM_LIB)(oscam-garbage.o) \
	$(OSCAM_LIB)(oscam-http-helpers.o) \
	$(OSCAM_LIB)(oscam-http.o) \
	$(OSCAM_LIB)(oscam-log.o) \
	$(OSCAM_LIB)(oscam-reader.o) \
	$(OSCAM_LIB)(oscam-simples.o) \
	$(OSCAM_LIB)(reader-bulcrypt.o) \
	$(OSCAM_LIB)(reader-common.o) \
	$(OSCAM_LIB)(reader-conax.o) \
	$(OSCAM_LIB)(reader-cryptoworks.o) \
	$(OSCAM_LIB)(reader-dre.o) \
	$(OSCAM_LIB)(reader-irdeto.o) \
	$(OSCAM_LIB)(reader-nagra.o) \
	$(OSCAM_LIB)(reader-nds.o) \
	$(OSCAM_LIB)(reader-seca.o) \
	$(OSCAM_LIB)(reader-tongfang.o) \
	$(OSCAM_LIB)(reader-viaccess.o) \
	$(OSCAM_LIB)(reader-videoguard-common.o) \
	$(OSCAM_LIB)(reader-videoguard1.o) \
	$(OSCAM_LIB)(reader-videoguard12.o) \
	$(OSCAM_LIB)(reader-videoguard2.o)

ifneq ($(USE_LIBUSB)$(LIBUSB),)
all:		prepare $(OSCAM_BIN) $(LIST_SMARGO_BIN)
else
all:		prepare $(OSCAM_BIN)
endif

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
|  CC_OPTS  = $(CC_OPTS)\n\
|  CC_WARN  = $(CC_WARN)\n\
|  CFLAGS   = $(CFLAGS)\n\
|  LDFLAGS  = $(LDFLAGS)\n\
|  LIBS     = $(LIBS)\n\
| Config:\n\
|  Addons   : $(shell ./config.sh --show addons)\n\
|  Protocols: $(shell ./config.sh --show protocols)\n\
|  Readers  : $(shell ./config.sh --show readers)\n\
|  Compiler : $(shell $(CC) --version 2>/dev/null | head -n 1)\n\
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

$(OSCAM_BIN): oscam.c $(ALGO_LIB) $(CSCRYPT_LIB) $(CSCTAPI_LIB) $(OSCAM_LIB)
	$(SAY) "LINK	$@"
	$(Q)$(CC) $(STD_DEFS) $(LDFLAGS) oscam.c $(OSCAM_LIB) $(ALGO_LIB) $(CSCRYPT_LIB) $(CSCTAPI_LIB) $(LIBS) -o $@
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
	$(SHELL) ./config.sh

menuconfig: config

clean:
	@-rm -rfv lib

distclean: clean
	@-rm -rfv Distribution/oscam-* Distribution/list_smargo-*

help:
	@-printf "\
OSCam ver: $(VER) rev: $(SVN_REV)\n\
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
\n\
   USE_PCSC=1      - Request linking with PCSC. The variables that control\n\
                     USE_PCSC=1 build are:\n\
                         PCSC_FLAGS='$(DEFAULT_PCSC_FLAGS)'\n\
                         PCSC_CFLAGS='$(DEFAULT_PCSC_FLAGS)'\n\
                         PCSC_LDFLAGS='$(DEFAULT_PCSC_FLAGS)'\n\
                         PCSC_LIB='$(DEFAULT_PCSC_LIB)'\n\
                     Using USE_PCSC=1 adds to '-pcsc' to PLUS_TARGET.\n\
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
                    -dumpmachine output. On your machine the target is set to\n\
                    '$(TARGET)'\n\
\n\
   PLUS_TARGET     - This variable is added to TARGET and it is set depending\n\
                     on the chosen USE_xxx (or DEBUG) flags. To disable adding\n\
                     PLUS_TARGET to TARGET, set NO_PLUS_TARGET=1\n\
\n\
   OSCAM_BIN=text  - This variable controls how the oscam binary will be named.\n\
                     Default OSCAM_BIN value is:\n\
                     '$(OSCAM_BIN)'\n\
                     For example you can run: 'make OSCAM_BIN=my-oscam'\n\
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
                    Example: 'make EXTRA_CFLAGS=-DBLAH=1 -I/opt/local'\n\
\n\
   EXTRA_LDLAGS   - Add text to LDLAGS (affects linking).\n\
                    Example: 'make EXTRA_LDLAGS=-Llibdir'\n\
\n\
   EXTRA_FLAGS    - Add text to both EXTRA_CFLAGS and EXTRA_LDFLAGS.\n\
                    Example: 'make EXTRA_FLAGS=-DWEBIF=1'\n\
\n\
   EXTRA_LIBS     - Add text to LIBS (affects linking).\n\
                    Example: 'make EXTRA_LIBS=-L./stapi -loscam_stapi'\n\
\n\
 Config target:\n\
   make config    - Start configuration utility.\n\
\n\
 Cleaning targets:\n\
   make clean     - Remove lib/ directory which contains built object files.\n\
   make distclean - Executes clean target and also removes binary files\n\
                    located in Distribution/ directory.\n\
\n\
 Build system files:\n\
   config.sh      - OSCam configuration. Run 'config.sh --help' to see\n\
                    available parameters or 'make config' to start GUI\n\
                    configuratior.\n\
   Makefile       - Main build system file.\n\
   Makefile.extra - Contains predefined targets.\n\
   Makefile.local - This file is included in Makefile and allows creation\n\
                    of local build system targets. See Makefile.extra for\n\
                    examples.\n\
   CMakeLists.txt - These files are used by 'cmake' build system.\n\
\n\
 Examples:\n\
   Build OSCam for SH4 (the compilers are in the path):\n\
     make CROSS=sh4-linux-\n\n\
   Build OSCam for SH4 (the compilers are in not in the path):\n\
     make sh4 CROSS_DIR=/opt/STM/STLinux-2.3/devkit/sh4/bin/\n\n\
     make CROSS_DIR=/opt/STM/STLinux-2.3/devkit/sh4/bin/ CROSS=sh4-linux-\n\n\
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
     make USE_LIBUSB=1 LIBUSB_LIB=\"-Llibusb-directory -llibusb.a\"\n\n\
   Build OSCam with static libcrypto:\n\
     make USE_LIBCRYPTO=1 LIBCRYPTO_LIB=\"-Lopenssl-build -llibcrypto.a\"\n\n\
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
