SUBDIRS = intl m4 po man

PYTHONREV=@PYTHONREV@
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

install-exec-local:
	mkdir -p $(DESTDIR)/$(bindir)
	ln -sf consolehelper $(DESTDIR)/$(bindir)/authconfig
	ln -sf consolehelper $(DESTDIR)/$(bindir)/authconfig-gtk
	ln -sf consolehelper $(DESTDIR)/$(bindir)/redhat-config-auth

install-data-local:
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
	$(INSTALL_DATA) $(srcdir)/authconfig.desktop $(DESTDIR)/$(applnkdir)/authconfig.desktop
	$(INSTALL_DATA) $(srcdir)/authconfig.desktop $(DESTDIR)/$(startheredir)/authconfig.desktop

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
	$(RM) $(DESTDIR)/$(applnkdir)/authconfig.desktop
	$(RM) $(DESTDIR)/$(startheredir)/authconfig.desktop
	$(RM) $(DESTDIR)$(pkgdatadir)/*.pyc
	rmdir $(DESTDIR)/$(applnkdir)
	rmdir $(DESTDIR)/$(startheredir)
	rmdir $(DESTDIR)/$(bindir)
	rmdir $(DESTDIR)/$(pamdir)
	rmdir $(DESTDIR)/$(consoledir)
	rmdir $(DESTDIR)/$(sysconfigdir)

ACLOCAL_AMFLAGS = -I m4
CFLAGS = @GLIB_CFLAGS@ @CFLAGS@ -I/usr/include/python@PYTHONREV@

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

EXTRA_DIST = authconfig.spec authconfig.pamd authconfig.console authconfig-gtk.console authconfig.desktop authconfig-gtk.py authconfig.glade config.rpath man/en/authconfig.8
