set -x
glib-gettextize -f -c
touch config.h.in
autoheader-2.53
libtoolize -f -c
aclocal-1.6
automake-1.6 -a
intltoolize -f
autoconf-2.53
