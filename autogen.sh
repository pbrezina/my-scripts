set -x
intltoolize -f -c
autoreconf --force --install
test -x mkinstalldirs || cp /usr/share/glib-2.0/gettext/mkinstalldirs .
