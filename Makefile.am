SUBDIRS = po man

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
pythonsite_PROGRAMS = authconfigmodule.so
pixmapdir = $(datadir)/pixmaps
pixmap_DATA = user_auth.png

install-exec-local:
	mkdir -p $(DESTDIR)/$(bindir)
	ln -sf consolehelper $(DESTDIR)/$(bindir)/authconfig
	ln -sf consolehelper $(DESTDIR)/$(bindir)/authconfig-gtk
	ln -sf consolehelper $(DESTDIR)/$(bindir)/redhat-config-auth

install-data-local: authconfig.desktop
	mkdir -p $(DESTDIR)/$(pamdir)
	mkdir -p $(DESTDIR)/$(consoledir)
	mkdir -p $(DESTDIR)/$(sysconfigdir)
	mkdir -p $(DESTDIR)/$(applnkdir)
	mkdir -p $(DESTDIR)/$(startheredir)
	$(INSTALL_DATA) $(srcdir)/authconfig.pamd $(DESTDIR)/$(pamdir)/authconfig
	$(INSTALL_DATA) $(srcdir)/authconfig.pamd $(DESTDIR)/$(pamdir)/authconfig-gtk
	$(INSTALL_DATA) $(srcdir)/authconfig.pamd $(DESTDIR)/$(pamdir)/redhat-config-auth
	$(INSTALL_DATA) $(srcdir)/authconfig.console $(DESTDIR)/$(consoledir)/authconfig
	$(INSTALL_DATA) $(srcdir)/authconfig-gtk.console $(DESTDIR)/$(consoledir)/authconfig-gtk
	$(INSTALL_DATA) $(srcdir)/authconfig-gtk.console $(DESTDIR)/$(consoledir)/redhat-config-auth
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
	$(RM) $(DESTDIR)/$(bindir)/redhat-config-auth
	$(RM) $(DESTDIR)/$(pamdir)/authconfig
	$(RM) $(DESTDIR)/$(pamdir)/authconfig-gtk
	$(RM) $(DESTDIR)/$(pamdir)/redhat-config-auth
	$(RM) $(DESTDIR)/$(consoledir)/authconfig
	$(RM) $(DESTDIR)/$(consoledir)/authconfig-gtk
	$(RM) $(DESTDIR)/$(consoledir)/redhat-config-auth
	$(RM) $(DESTDIR)/$(sysconfigdir)/authconfig
	$(RM) $(DESTDIR)$(pkgdatadir)/*.pyc
	rmdir $(DESTDIR)/$(applnkdir)
	rmdir $(DESTDIR)/$(startheredir)
	rmdir $(DESTDIR)/$(bindir)
	rmdir $(DESTDIR)/$(pamdir)
	rmdir $(DESTDIR)/$(consoledir)
	rmdir $(DESTDIR)/$(sysconfigdir)

CFLAGS = @GLIB_CFLAGS@ @CFLAGS@ @PYTHON_CFLAGS@

authconfig_SOURCES = \
	authconfig.c \
	authinfo.c \
	authinfo.h \
	dnsclient.c \
	dnsclient.h \
	localpol.h \
	shvar.c \
	shvar.h
authconfig_LDFLAGS = @GLIB_LIBS@ @NEWT_LIBS@ @POPT_LIBS@ @LDFLAGS@

authconfigmodule_so_SOURCES = \
	authconfigmodule.c \
	authinfo.c \
	authinfo.h \
	dnsclient.c \
	dnsclient.h \
	shvar.c \
	shvar.h
authconfigmodule_so_LDFLAGS = -shared @GLIB_LIBS@ @LDFLAGS@

EXTRA_DIST = authconfig.spec authconfig.pamd authconfig.console authconfig-gtk.console authconfig.desktop authconfig-gtk.py authconfig.glade man/en/authconfig.8 NOTES utf8ify-mo intltool-extract.in intltool-merge.in intltool-update.in user_auth.png

CVSTAG=r-$(shell rpm -q --specfile authconfig.spec --queryformat '%{version}\n' | head -1 | sed 's,\.,-,g')
tag:
	cvs tag -cFR $(CVSTAG)

archive:
	rm -fr /tmp/$(PACKAGE) $(PACKAGE)-$(VERSION).tar.gz
	dir=`pwd` ; \
	root=`cat CVS/Root` ; \
	cd /tmp ; \
	cvs -d "$$root" export -r $(CVSTAG) -d $(PACKAGE) $(PACKAGE) ; \
	cd $(PACKAGE) ; \
	./autogen.sh ; \
	./configure ; \
	aclocal ; \
	make dist ; \
	mv $(PACKAGE)-$(VERSION).tar.gz $$dir
