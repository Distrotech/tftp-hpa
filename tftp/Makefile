all: tftp

SRCROOT = ..

-include ../MCONFIG
include ../MRULES

OBJS = tftp.o main.o tftpsubs.o

tftp: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(TFTP_LIBS) -o $@

$(OBJS): tftpsubs.h

install: tftp
	mkdir -p $(INSTALLROOT)$(BINDIR) $(INSTALLROOT)$(MANDIR)/man1
	$(INSTALL_PROGRAM) -s tftp $(INSTALLROOT)$(BINDIR)
	$(INSTALL_DATA)    tftp.1  $(INSTALLROOT)$(MANDIR)/man1

clean:
	rm -f *.o tftp

distclean: clean
	rm -f *~
