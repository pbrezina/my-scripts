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

install-data-hook:
	python@PYTHONREV@ -c "import compileall; compileall.compile_dir(\""$(DESTDIR)$(pkgdatadir)"\", 2, \""$(pkgdatadir)"\", 1)"

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
	$(INSTALL_DATA) $(srcdir)/authconfig.desktop $(DESTDIR)/$(applnkdir)
	$(INSTALL_DATA) $(srcdir)/authconfig.desktop $(DESTDIR)/$(startheredir)

ACLOCAL_AMFLAGS = -I m4
CFLAGS = @GLIB_CFLAGS@ @CFLAGS@ -I$(includedir)/python@PYTHONREV@

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
