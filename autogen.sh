set -x
glib-gettextize -f -c
touch config.h.in
autoheader
libtoolize -f -c
aclocal
automake -a
intltoolize -f
autoconf
test -x mkinstalldirs || cp /usr/share/gettext/mkinstalldirs .
./configure $@
