set -x
gettextize --intl -f --no-changelog
autoheader
automake -a
libtoolize -f -c
aclocal
intltoolize
autoconf
