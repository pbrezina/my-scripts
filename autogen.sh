set -x
glib-gettextize -f -c
touch config.h.in
autoheader
libtoolize -f -c
aclocal
automake -a
intltoolize -f
autoconf
./configure $@
