VERSION=$(shell awk '/Version:/ { print $$2 }' authconfig.spec)
CVSTAG = r$(subst .,-,$(VERSION))
PROGNAME = authconfig

GLIBCONFIG=glib-config
CFLAGS += -Wall -DPACKAGE=\"$(PROGNAME)\" -DVERSION=\"$(VERSION)\" `$(GLIBCONFIG) --cflags` -g3 $(RPM_OPT_FLAGS) $(EXTRA_CFLAGS)
LOADLIBES = `$(GLIBCONFIG) --libs` -lnewt -lpopt -lresolv
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

authconfig: $(PROGNAME).o authinfo.o shvar.o dnsclient.o
	$(CC) -o $(PROGNAME) $^ $(LOADLIBES)

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
	cvs -d `cat CVS/Root` tag -cF $(CVSTAG) .
	@rm -rf /tmp/$(PROGNAME)-$(VERSION) /tmp/$(PROGNAME)
	@dir=$$PWD; cd /tmp; cvs -d `cat $$dir/CVS/Root` export -r$(CVSTAG) $(PROGNAME)
	@mv /tmp/$(PROGNAME) /tmp/$(PROGNAME)-$(VERSION)
	@dir=$$PWD; cd /tmp; tar cvzf $$dir/$(PROGNAME)-$(VERSION).tar.gz \
		$(PROGNAME)-$(VERSION)
	@rm -rf /tmp/$(PROGNAME)-$(VERSION)
	@echo "The archive is in $(PROGNAME)-$(VERSION).tar.gz"
