# -*- coding: utf-8 -*-
#
#    Authors:
#        Pavel Březina <pbrezina@redhat.com>
#
#    Copyright (C) 2019 Red Hat
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


class Author(object):
    def __init__(self, github_login):
        (self.name, self.email) = self._map_login(github_login)
        self.login = github_login

    def _map_login(self, github_login):
        logins = {
            'abbra': ('Alexander Bokovoy', 'abokovoy@redhat.com'),
            'alexey-tikhonov': ('Alexey Tikhonov', 'atikhono@redhat.com'),
            'jhrozek': ('Jakub Hrozek', 'jhrozek@redhat.com'),
            'mrniranjan': ('Niranjan Mallapadi', 'mrniranjan@redhat.com'),
            'mzidek-rh': ('Michal Židek', 'mzidek@redhat.com'),
            'mzidek-gh': ('Michal Židek', 'mzidek@redhat.com'),
            'pbrezina': ('Pavel Březina', 'pbrezina@redhat.com'),
            'sgallagher': ('Stephen Gallagher ', 'sgallagher@redhat.com'),
            'sumit-bose': ('Sumit Bose', 'sbose@redhat.com'),
            'thalman': ('Tomáš Halman', 'thalman@redhat.com'),
            'elkoniu': ('Pawel Polawski', 'ppolawsk@redhat.com'),
            'ikerexxe': ('Iker Pedrosa', 'ipedrosa@redhat.com'),
            'sgoveas': ('Steeve Goveas', 'sgoveas@redhat.com'),
            'madhuriupadhye': ('Madhuri Upadhye', 'mupadhye@redhat.com'),
            'shridhargadekar': ('Shridhar Gadekar', 'sgadekar@redhat.com'),
            'justin-stephenson': ('Justin Stephenson', 'jstephen@redhat.com'),
            'aborah-sudo': ('Anuj Borah', 'aborah@redhat.com'),
            'jakub-vavra-cz': ('Jakub Vávra', 'jvavra@redhat.com'),
            'sidecontrol': ('Dan Lavu', 'dlavu@redhat.com'),
            'danlavu': ('Dan Lavu', 'dlavu@redhat.com'),
            'spoore1': ('Scott Poore', 'spoore@redhat.com'),
            'kaushikub': ('Kaushik Banerjee', 'kbanerje@redhat.com'),
            'aplopez': ('Alejandro López', 'allopez@redhat.com'),
            'andreboscatto': ('Andre Boscatto', 'aboscatt@redhat.com'),
        }

        author = logins.get(github_login, None)
        if author is None:
            raise ValueError('Unknown author: {}'.format(github_login))

        return author

    def __str__(self):
        return '{} <{}>'.format(self.name, self.email)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, value):
        if not isinstance(value, self.__class__):
            return False

        return self.login == value.login

    def __ne__(self, value):
        return not self.__eq__(value)

    def __lt__(self, value):
        return self.name < value.name

    def __hash__(self):
        return hash(self.login)
