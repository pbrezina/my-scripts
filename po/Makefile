INSTALL= /usr/bin/install -c
INSTALL_PROGRAM= ${INSTALL}
INSTALL_DATA= ${INSTALL} -m 644
datadir=/usr/share
INSTALLNLSDIR=$(datadir)/locale

MSGMERGE = msgmerge

NLSPACKAGE = authconfig

CATALOGS = $(shell ls *.po | sed 's/po/mo/')

POTFILES  = ../authconfig.c ../authinfo.h ../localpol.h ../glade.strings

all: $(NLSPACKAGE).pot $(CATALOGS)

$(NLSPACKAGE).pot: $(POTFILES)
	xgettext --default-domain=$(NLSPACKAGE) \
		--add-comments --keyword=i18n --keyword=N_ $(POTFILES)
	if cmp -s $(NLSPACKAGE).po $(NLSPACKAGE).pot; then \
	    rm -f $(NLSPACKAGE).po; \
	else \
	    mv $(NLSPACKAGE).po $(NLSPACKAGE).pot; \
	fi


update-po: Makefile
	$(MAKE) $(NLSPACKAGE).pot
	catalogs='$(CATALOGS)'; \
	for cat in $$catalogs; do \
		lang=`echo $$cat | sed 's/.mo//'`; \
		if $(MSGMERGE) $$lang.po $(NLSPACKAGE).pot > $$lang.pot ; then \
			echo "$(MSGMERGE) of $$lang succeeded" ; \
			mv -f $$lang.pot $$lang.po ; \
		else \
			echo "$(MSGMERGE) of $$lang failed" ; \
			rm -f $$lang.pot ; \
		fi \
	done

refresh-po: Makefile
	catalogs='$(CATALOGS)'; \
	for cat in $$catalogs; do \
		lang=`echo $$cat | sed 's/.mo//'`; \
		if $(MSGMERGE) $$lang.po $(NLSPACKAGE).pot > $$lang.pot ; then \
			echo "$(MSGMERGE) of $$lang succeeded" ; \
			mv -f $$lang.pot $$lang.po ; \
		else \
			echo "$(MSGMERGE) of $$lang failed" ; \
			rm -f $$lang.pot ; \
		fi \
	done

clean:
	rm -f *mo $(NLSPACKAGE).pot

distclean: clean
	rm -f .depend Makefile

depend:

install:
	catalogs='$(CATALOGS)'; \
	for cat in $$catalogs""; do \
		[ -z "$$cat" ] && continue; \
		l=`basename $$cat .mo`; \
		mkdir -p $(INSTALLNLSDIR)/$$l/LC_MESSAGES; \
		if [ -f $$cat ]; then \
		        $(INSTALL) -m 644 $$cat $(INSTALLNLSDIR)/$$l/LC_MESSAGES/$(NLSPACKAGE).mo; \
		fi \
	done

%.mo: %.po
	msgfmt -v -o $@ $<
