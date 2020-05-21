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

class Label(object):
    def __init__(self, name, color, description):
        self.name = name
        self.color = color
        self.description = description

    def create(self, repo):
        repo.create_label(
            name=self.name,
            color=self.color,
            description=self.description
        )

    def add(self, repo, issue):
        try:
            self.create(repo.api)
        except Exception:
            pass

        issue.add_to_labels(self.name)

    def remove(self, issue):
        issue.remove_from_labels(self.name)

    def __eq__(self, value):
      if type(value) is str:
        return self.name == value

      if not isinstance(value, self.__class__):
        return False

      return self.name == value.name

    def __ne__(self, value):
        return not self.__eq__(value)

    def __str__(self):
      return self.name

    def __hash__(self):
        return hash(self.name)

class WellKnownLabels(object):
    def __init__(self):
        self.accepted = Label('Accepted', '0e8a16', 'Pull request is accepted')
        self.ready = Label('Ready to push', 'c5def5', 'Ready to push')
        self.conflict = Label('Conflict', 'ff0000', 'Conflicts with target branch')
        self.pushed = Label('Pushed', 'c5def5', 'Pull request has been pushed')
        self.fixed = Label('Closed: Fixed', 'ededed', 'Issue was closed as fixed')
