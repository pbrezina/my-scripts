VERSION=$(shell awk '/Version:/ { print $$2 }' authconfig.spec)
CVSTAG = r$(subst .,-,$(VERSION))
PROGNAME = authconfig

CFLAGS += -Wall -DVERSION=\"$(VERSION)\" `glib-config --cflags` -ggdb $(RPM_OPT_FLAGS) $(EXTRA_CFLAGS)
LOADLIBES = `glib-config --libs` -lnewt -lpopt
SUBDIRS = po man

datadir=/usr/share
mandir=/usr/man
sbindir=/usr/sbin

all:	subdirs $(PROGNAME)

subdirs:
	for d in $(SUBDIRS); do \
	(cd $$d; $(MAKE)) \
	|| case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac;\
	done && test -z "$$fail"

authconfig: $(PROGNAME).o authinfo.o shvar.o

install:
	mkdir -p $(sbindir) $(mandir)/man8
	mkdir -p $(INSTROOT)$(sysconfdir)/pam.d
	install -m 755 $(PROGNAME) $(sbindir)/$(PROGNAME)
	for d in $(SUBDIRS); do \
	(cd $$d; $(MAKE) sbindir=$(sbindir) install) \
	    || case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac;\
	done && test -z "$$fail"

clean:
	rm -f $(PROGNAME) *.o
	make -C po clean

archive:
	cvs tag -F $(CVSTAG) .
	@rm -rf /tmp/$(PROGNAME)-$(VERSION) /tmp/$(PROGNAME)
	@cd /tmp; cvs export -r$(CVSTAG) $(PROGNAME)
	@mv /tmp/$(PROGNAME) /tmp/$(PROGNAME)-$(VERSION)
	@dir=$$PWD; cd /tmp; tar cvzf $$dir/$(PROGNAME)-$(VERSION).tar.gz \
		$(PROGNAME)-$(VERSION)
	@rm -rf /tmp/$(PROGNAME)-$(VERSION)
	@echo "The archive is in $(PROGNAME)-$(VERSION).tar.gz"
