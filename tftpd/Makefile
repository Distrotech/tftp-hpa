all: tftpd tftpd.8

SRCROOT = ..
VERSION = $(shell cat ../version)

-include ../MCONFIG
include ../MRULES

OBJS = tftpd.o tftpsubs.o recvfrom.o misc.o $(TFTPDOBJS)

tftpd: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(TFTPD_LIBS) -o $@

tftpsubs.c: 
	ln -sf ../tftp/tftpsubs.c .
tftpsubs.h: 
	ln -sf ../tftp/tftpsubs.h .

$(OBJS): tftpsubs.h

tftpd.8: tftpd.8.in ../version
	sed -e 's/@@VERSION@@/$(VERSION)/g' < $< > $@

install: all
	mkdir -p $(INSTALLROOT)$(SBINDIR) $(INSTALLROOT)$(MANDIR)/man8
	$(INSTALL_PROGRAM) tftpd $(INSTALLROOT)$(SBINDIR)/in.tftpd
	$(INSTALL_DATA)    tftpd.8 $(INSTALLROOT)$(MANDIR)/man8/in.tftpd.8
	cd $(INSTALLROOT)$(MANDIR)/man8 && ln -sf in.tftpd.8 tftpd.8

clean:
	rm -f *.o tftpd tftpsubs.c tftpsubs.h tftpd.8

distclean: clean
	rm -f *~
