VERSION=$(shell awk '/Version:/ { print $$2 }' authconfig.spec)
CVSTAG = r$(subst .,-,$(VERSION))
PACKAGE = authconfig
BINARIES = authconfig authconfig-gtk
PYTHONMODULES = authconfigmodule.so
PYTHONREV=2.2
PYTHONINC=/usr/include/python$(PYTHONREV)
PYTHONLIB=/usr/lib/python$(PYTHONREV)/site-packages

CFLAGS = -g3 -Wall -fPIC -DPACKAGE=\"$(PACKAGE)\" -DVERSION=\"$(VERSION)\"
CFLAGS += $(shell pkg-config --cflags glib-2.0 libglade-2.0) -I$(PYTHONINC)
CFLAGS += -DG_DISABLE_DEPRECATED -DGTK_DISABLE_DEPRECATED $(RPM_OPT_FLAGS)
RESOLVLIBS=-lresolv
LIBS = -lnewt -lpopt $(RESOLVLIBS)
GLIBLIBS = $(shell pkg-config --libs glib-2.0)
LIBGLADELIBS = $(shell pkg-config --libs libglade-2.0)
SUBDIRS = po man

datadir=/usr/share
mandir=/usr/man
sbindir=/usr/sbin
CFLAGS += -DDATADIR=\"$(datadir)\"

all:	subdirs $(BINARIES) $(PYTHONMODULES)

subdirs:
	for d in $(SUBDIRS); do \
	(cd $$d; $(MAKE)) \
	|| case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac;\
	done && test -z "$$fail"

authconfig: authconfig.o authinfo.o shvar.o dnsclient.o
	$(CC) -o $@ $^ $(GLIBLIBS) $(LIBS)

authconfig-gtk: authconfig-gtk.o authinfo.o shvar.o dnsclient.o
	$(CC) -o $@ $^ $(LIBGLADELIBS) $(LIBS)

authconfigmodule.so: authconfigmodule.o authinfo.o shvar.o dnsclient.o
	$(CC) -o $@ -shared -fPIC $^ $(GLIBLIBS) $(RESOLVLIBS)
	python$(PYTHONREV) -c 'import authconfig'

install:
	mkdir -p $(sbindir) $(mandir)/man8 $(datadir)/$(PACKAGE)
	mkdir -p $(INSTROOT)$(sysconfdir)/pam.d
	mkdir -p $(INSTROOT)$(PYTHONLIB)
	install -m 755 $(BINARIES) $(sbindir)/
	install -m 755 $(PYTHONMODULES) $(INSTROOT)$(PYTHONLIB)/
	install -m 644 $(PACKAGE).glade2 $(datadir)/$(PACKAGE)/$(PACKAGE).glade
	for d in $(SUBDIRS); do \
	(cd $$d; $(MAKE) sbindir=$(sbindir) install) \
	    || case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac;\
	done && test -z "$$fail"

clean:
	rm -f authconfig authconfig-gtk *.o
	make -C po clean

archive:
	cvs -d `cat CVS/Root` tag -cFR $(CVSTAG) .
	@rm -rf /tmp/$(PACKAGE)-$(VERSION) /tmp/$(PACKAGE)
	@dir=$$PWD; cd /tmp; cvs -d `cat $$dir/CVS/Root` export -r$(CVSTAG) $(PACKAGE)
	@mv /tmp/$(PACKAGE) /tmp/$(PACKAGE)-$(VERSION)
	@dir=$$PWD; cd /tmp; tar cvzf $$dir/$(PACKAGE)-$(VERSION).tar.gz \
		$(PACKAGE)-$(VERSION)
	@rm -rf /tmp/$(PACKAGE)-$(VERSION)
	@echo "The archive is in $(PACKAGE)-$(VERSION).tar.gz"
