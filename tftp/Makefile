all: tftp

include ../MCONFIG
include ../MRULES

OBJS = tftp.o main.o tftpsubs.o

tftp: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

$(OBJS): tftpsubs.h

install: tftp
	$(INSTALL_PROGRAM) -s tftp $(INSTALLROOT)$(BINDIR)
	$(INSTALL_DATA)    tftp.1  $(INSTALLROOT)$(MANDIR)/man1

clean:
	rm -f *.o tftp

spotless: clean
	rm -f *~
