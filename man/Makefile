all:

install:
	install -m 644 en/authconfig.8 $(INSTROOT)/usr/man/man8
	for d in $(shell ls | grep -v en | grep -v Makefile | grep -v CVS)""; do \
		[ -z "$$d" ] && continue;
	        mkdir -p  $(INSTROOT)/usr/man/$$d/man8 ; \
		install -m 644 $$d/authconfig.8 $(INSTROOT)/usr/man/$$d/man8 ; \
	done

clean:
