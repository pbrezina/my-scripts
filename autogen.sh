set -x -e
gettextize --intl
autoheader
automake-1.5 -a
aclocal-1.5
intltoolize
autoconf-2.53
