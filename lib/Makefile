#
# Extra functions which may not be available everywhere
#

SRCROOT = ..

-include ../MCONFIG
include ../MRULES

all:	libxtra.a

install:

clean:
	-rm -f *.a *.o *.obj *.exe

distclean: clean
	-rm -f *~

libxtra.a: $(LIBOBJS)
	-rm -f libxtra.a
	$(AR) libxtra.a $(LIBOBJS)
	$(RANLIB) libxtra.a


