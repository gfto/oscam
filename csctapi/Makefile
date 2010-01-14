SHELL		= /bin/sh

GENERAL		= Makefile config.h

LIBDIR		= ../lib
LIBFILE1	= $(LIBDIR)/libcsctapi-$(TYP).a

OBJECTS1	= $(LIBFILE1)(apdu.o) \
		  $(LIBFILE1)(atr.o) \
		  $(LIBFILE1)(cardterminal.o) \
		  $(LIBFILE1)(ct_list.o) \
		  $(LIBFILE1)(ct_slot.o) \
		  $(LIBFILE1)(ctapi.o) \
		  $(LIBFILE1)(icc_async.o) \
		  $(LIBFILE1)(ifd_towitoko.o) \
			$(LIBFILE1)(ifd_cool.o) \
		  $(LIBFILE1)(ifd_sci.o) \
		  $(LIBFILE1)(ifd_phoenix.o) \
		  $(LIBFILE1)(io_serial.o) \
		  $(LIBFILE1)(pps.o) \
		  $(LIBFILE1)(protocol_t0.o) \
		  $(LIBFILE1)(protocol_t1.o) \
		  $(LIBFILE1)(t1_block.o)

all:		$(LIBFILE1) 

$(LIBFILE1):	$(OBJECTS1)
		-@$(RANLIB) $@

$(OBJECTS1):	$(GENERAL)

.c.a:
		$(CC) $(CFLAGS) $<
		$(AR) $(ARFLAGS) $@ $*.o
		-@rm -f $*.o

.SUFFIXES:	.o .c .a
