set -x -e
gettextize --intl
automake-1.5 -a
aclocal-1.5
intltoolize
autoheader-2.53
autoconf-2.53
