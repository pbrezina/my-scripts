set -x
gettextize --intl -f
autoheader
automake-1.5 -a
libtoolize
aclocal-1.5
intltoolize
autoconf-2.53
