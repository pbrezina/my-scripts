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

import re

from util.upstream.label import Label

class Issue(object):
    def __init__(self, repo, id):
        self.repo = repo
        self.id = id
        self.api = self.repo.api.get_issue(int(id))
        self.title = self.api.title
        self.url = self.api.html_url
        self._labels = None

    @property
    def labels(self):
        if self._labels is not None:
            return self._labels

        self._labels = [Label(x.name, x.color, x.description) for x in self.api.get_labels()]
        return self._labels

    def comment(self, msg):
        self.api.create_comment(msg)

    def close(self):
        self.api.edit(state='closed')

    def add_label(self, label):
        if label in self.labels:
            return

        label.add(self.repo, self.api)
        self._labels.append(label)

    def remove_label(self, label):
        if label not in self.labels:
            return

        label.remove(self.api)
        self._labels.remove(label)

    @staticmethod
    def fromURL(repo, url):
        matches = re.findall(r'^https://github.com/{}/issues/(\d+)$'.format(repo.name), url)
        if not matches:
            raise ValueError('Unknown issue link: {}'.format(url))

        return Issue(repo, matches[0])

    def __str__(self):
        return '{} {}'.format(self.url, self.title)

    def __repr__(self):
        return self.__str__()

    def __lt__(self, value):
        return self.id < value.id

    def __eq__(self, value):
        if not isinstance(value, self.__class__):
            return False

        return self.id == value.id

    def __ne__(self, value):
        return not self.__eq__(value)

    def __hash__(self):
        return hash(self.id)
