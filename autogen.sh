set -x
gettextize --intl -f
autoheader
automake -a
libtoolize -f -c
aclocal -I m4
intltoolize
autoconf
