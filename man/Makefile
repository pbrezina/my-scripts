all:

mandir=/usr/man

install:
	install -m 644 en/authconfig.8 $(DESTDIR)$(mandir)/man8
	for d in $(shell ls | grep -v en | grep -v Makefile | grep -v CVS)""; do \
		[ -z "$$d" ] && continue; \
	        mkdir -p  $(DESTDIR)$(mandir)/$$d/man8 ; \
		install -m 644 $$d/authconfig.8 $(DESTDIR)$(mandir)/$$d/man8 ; \
	done

clean:
