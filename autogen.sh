set -x
gettextize --intl -f
autoheader-2.53
automake-1.5 -a
libtoolize -f -c
aclocal-1.5
intltoolize
autoconf-2.53
