SHELL		= /bin/sh

GENERAL		= Makefile

LIBDIR		= ../lib
LIBFILE1	= $(LIBDIR)/libcsctapi-$(TYP).a

OBJECTS1	= $(LIBFILE1)(atr.o) \
		  $(LIBFILE1)(icc_async.o) \
                  $(LIBFILE1)(ifd_cool.o) \
		  $(LIBFILE1)(ifd_sci.o) \
		  $(LIBFILE1)(ifd_phoenix.o) \
		  $(LIBFILE1)(ifd_sc8in1.o) \
		  $(LIBFILE1)(ifd_mp35.o) \
		  $(LIBFILE1)(io_serial.o) \
		  $(LIBFILE1)(protocol_t0.o) \
		  $(LIBFILE1)(protocol_t1.o) \
		  $(LIBFILE1)(t1_block.o) \
		  $(LIBFILE1)(ifd_smartreader.o)

all:		$(LIBFILE1) 

$(LIBFILE1):	$(OBJECTS1)
		-@$(RANLIB) $@

$(OBJECTS1):	$(GENERAL)

.c.a:
		$(CC) $(CFLAGS) $<
		$(AR) $(ARFLAGS) $@ $*.o
		-@rm -f $*.o

.SUFFIXES:	.o .c .a
