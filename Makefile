# You can do "make SUB=blah" to make only a few, or edit here, or both
# You can also run make directly in the subdirs you want.

SUB =   tftp tftpd

%.build:
	$(MAKE) -C $(patsubst %.build, %, $@)

%.install:
	$(MAKE) -C $(patsubst %.install, %, $@) install

%.clean:
	$(MAKE) -C $(patsubst %.clean, %, $@) clean

%.spotless:
	$(MAKE) -C $(patsubst %.spotless, %, $@) spotless

all:      $(patsubst %, %.build, $(SUB))

install:  $(patsubst %, %.install, $(SUB))

clean:    $(patsubst %, %.clean, $(SUB))

spotless: $(patsubst %, %.spotless, $(SUB))
	rm -f MCONFIG config.* *~
