SUBDIRS = po man
CONFIGURE_DEPENDENCIES = $(top_srcdir)/authconfig.spec

@INTLTOOL_DESKTOP_RULE@

PYTHONREV=@PYTHONREV@
pythonincdir = $(includedir)/python@PYTHONREV@
pythonsitedir = $(libdir)/python@PYTHONREV@/site-packages
pamdir = $(sysconfdir)/pam.d
consoledir = $(sysconfdir)/security/console.apps
sysconfigdir = $(sysconfdir)/sysconfig
applnkdir = $(sysconfdir)/X11/applnk/System
startheredir = $(sysconfdir)/X11/sysconfig

sbin_PROGRAMS = authconfig
pkgdata_SCRIPTS = authconfig-gtk.py
pkgdata_DATA = authconfig.glade
pythonsite_LTLIBRARIES = authconfigmodule.la
noinst_LTLIBRARIES = libauthconfig.la
pixmapdir = $(datadir)/pixmaps
pixmap_DATA = user_auth.png

install-exec-local:
	mkdir -p $(DESTDIR)/$(bindir)
	ln -sf consolehelper $(DESTDIR)/$(bindir)/authconfig
	ln -sf consolehelper $(DESTDIR)/$(bindir)/authconfig-gtk
	ln -sf consolehelper $(DESTDIR)/$(bindir)/system-config-authentication

install-data-local: authconfig.desktop
	mkdir -p $(DESTDIR)/$(pamdir)
	mkdir -p $(DESTDIR)/$(consoledir)
	mkdir -p $(DESTDIR)/$(sysconfigdir)
	mkdir -p $(DESTDIR)/$(applnkdir)
	mkdir -p $(DESTDIR)/$(startheredir)
	$(INSTALL_DATA) $(srcdir)/authconfig.pamd $(DESTDIR)/$(pamdir)/authconfig
	$(INSTALL_DATA) $(srcdir)/authconfig-gtk.pamd $(DESTDIR)/$(pamdir)/authconfig-gtk
	$(INSTALL_DATA) $(srcdir)/authconfig-gtk.pamd $(DESTDIR)/$(pamdir)/system-config-authentication
	$(INSTALL_DATA) $(srcdir)/authconfig.console $(DESTDIR)/$(consoledir)/authconfig
	$(INSTALL_DATA) $(srcdir)/authconfig-gtk.console $(DESTDIR)/$(consoledir)/authconfig-gtk
	$(INSTALL_DATA) $(srcdir)/authconfig-gtk.console $(DESTDIR)/$(consoledir)/system-config-authentication
	touch $(DESTDIR)/$(sysconfigdir)/authconfig
	mkdir -p $(DESTDIR)/$(datadir)/applications
	desktop-file-install --vendor redhat \
		--add-category=X-Red-Hat-Base \
		--add-category=Application \
		--add-category=System \
		--dir=$(DESTDIR)$(datadir)/applications \
		authconfig.desktop

uninstall-local:
	$(RM) $(DESTDIR)/$(bindir)/authconfig
	$(RM) $(DESTDIR)/$(bindir)/authconfig-gtk
	$(RM) $(DESTDIR)/$(bindir)/system-config-authentication
	$(RM) $(DESTDIR)/$(pamdir)/authconfig
	$(RM) $(DESTDIR)/$(pamdir)/authconfig-gtk
	$(RM) $(DESTDIR)/$(pamdir)/system-config-authentication
	$(RM) $(DESTDIR)/$(consoledir)/authconfig
	$(RM) $(DESTDIR)/$(consoledir)/authconfig-gtk
	$(RM) $(DESTDIR)/$(consoledir)/system-config-authentication
	$(RM) $(DESTDIR)/$(sysconfigdir)/authconfig
	$(RM) $(DESTDIR)$(pkgdatadir)/*.pyc
	rmdir $(DESTDIR)/$(applnkdir)
	rmdir $(DESTDIR)/$(startheredir)
	rmdir $(DESTDIR)/$(bindir)
	rmdir $(DESTDIR)/$(pamdir)
	rmdir $(DESTDIR)/$(consoledir)
	rmdir $(DESTDIR)/$(sysconfigdir)

AM_CFLAGS = @GLIB_CFLAGS@ @CFLAGS@ @PYTHON_CFLAGS@ -Wall

libauthconfig_la_SOURCES = \
	authinfo.c \
	authinfo.h \
	dnsclient.c \
	dnsclient.h \
	shvar.c \
	shvar.h

authconfig_SOURCES = authconfig.c localpol.h
authconfig_LDADD = libauthconfig.la
authconfig_LDFLAGS = @GLIB_LIBS@ @NEWT_LIBS@ @POPT_LIBS@ @LDFLAGS@

authconfigmodule_la_SOURCES = authconfigmodule.c
authconfigmodule_la_LIBADD = libauthconfig.la
authconfigmodule_la_LDFLAGS = -module -avoid-version -export-dynamic @GLIB_LIBS@ @LDFLAGS@

EXTRA_DIST = authconfig.spec authconfig.pamd authconfig-gtk.pamd authconfig.console authconfig-gtk.console authconfig.desktop.in authconfig-gtk.py authconfig.glade man/en/authconfig.8 NOTES utf8ify-mo intltool-extract.in intltool-merge.in intltool-update.in user_auth.png README.samba3 mkinstalldirs authconfig.glade.h
DISTCLEANFILES = intltool-extract intltool-merge intltool-update authconfig.desktop

VERSION=$(shell rpm -q --specfile $(top_srcdir)/authconfig.spec --qf '%{version}\n' | head -n1)
TAG=$(shell echo r-$(VERSION) | sed 's,\.,-,g')
distdir=$(PACKAGE)-$(VERSION)

tag:
	cvs tag -cR $(TAG)

force-tag forcetag:
	cvs tag -cFR $(TAG)

archive:
	rm -fr /tmp/$(PACKAGE) $(PACKAGE)-$(VERSION).tar.gz
	dir=`pwd` ; \
	root=`cat CVS/Root` ; \
	cd /tmp ; \
	cvs -d "$$root" export -r $(TAG) -d $(PACKAGE) $(PACKAGE) ; \
	cd $(PACKAGE) ; \
	./autogen.sh ; \
	./configure ; \
	aclocal ; \
	make dist ; \
	mv $(distdir).tar.gz $$dir
