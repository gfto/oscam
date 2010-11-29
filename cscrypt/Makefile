SHELL		= /bin/sh

GENERAL		= Makefile cscrypt.h des.h bn.h

LIBDIR		= ../lib
LIBFILE1	= $(LIBDIR)/libcscrypt-$(TYP).a

OBJECTS1	= $(LIBFILE1)(md5.o) \
		  $(LIBFILE1)(crc32.o) \
		  $(LIBFILE1)(des.o) \
		  $(LIBFILE1)(bn_add.o) \
		  $(LIBFILE1)(bn_asm.o) \
		  $(LIBFILE1)(bn_ctx.o) \
		  $(LIBFILE1)(bn_div.o) \
		  $(LIBFILE1)(bn_exp.o) \
		  $(LIBFILE1)(bn_lib.o) \
		  $(LIBFILE1)(bn_mul.o) \
		  $(LIBFILE1)(bn_print.o) \
		  $(LIBFILE1)(bn_shift.o) \
		  $(LIBFILE1)(bn_sqr.o) \
		  $(LIBFILE1)(bn_word.o) \
		  $(LIBFILE1)(i_cbc.o) \
		  $(LIBFILE1)(i_skey.o) \
		  $(LIBFILE1)(mem.o) \
		  $(LIBFILE1)(rc6.o) \
		  $(LIBFILE1)(i_ecb.o)

all:		$(LIBFILE1)

$(LIBFILE1):	$(OBJECTS1)
		-@$(RANLIB) $@

$(OBJECTS1):	$(GENERAL)

.c.a:
		$(CC) $(CFLAGS) $<
		$(AR) $(ARFLAGS) $@ $*.o
		-@rm -f $*.o

.SUFFIXES:	.o .c .a
