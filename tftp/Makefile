all: tftp tftp.1

SRCROOT = ..
VERSION = $(shell cat ../version)

-include ../MCONFIG
include ../MRULES

OBJS = tftp.o main.o tftpsubs.o

tftp: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(TFTP_LIBS) -o $@

$(OBJS): tftpsubs.h

tftp.1: tftp.1.in ../version
	sed -e 's/@@VERSION@@/$(VERSION)/g' < $< > $@

install: all
	mkdir -p $(INSTALLROOT)$(BINDIR) $(INSTALLROOT)$(MANDIR)/man1
	$(INSTALL_PROGRAM) tftp $(INSTALLROOT)$(BINDIR)
	$(INSTALL_DATA)    tftp.1  $(INSTALLROOT)$(MANDIR)/man1

clean:
	rm -f *.o tftp tftp.1

distclean: clean
	rm -f *~
