all: tftpd

-include ../MCONFIG
-include ../MRULES

OBJS = tftpd.o tftpsubs.o recvfrom.o misc.o $(TFTPDOBJS)

tftpd: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

tftpsubs.c: 
	ln -sf ../tftp/tftpsubs.c .
tftpsubs.h: 
	ln -sf ../tftp/tftpsubs.h .

$(OBJS): tftpsubs.h

install: tftpd
	$(INSTALL_PROGRAM) tftpd $(INSTALLROOT)$(SBINDIR)/in.tftpd
	$(INSTALL_DATA)    tftpd.8 $(INSTALLROOT)$(MANDIR)/man8/in.tftpd.8
	ln -sf in.tftpd.8 $(INSTALLROOT)$(MANDIR)/man8/tftpd.8

clean:
	rm -f *.o tftpd tftpsubs.c tftpsubs.h

distclean: clean
	rm -f *~
