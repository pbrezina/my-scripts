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

class Issue(object):
    def __init__(self, repo, id):
        self.repo = repo
        self.id = id
        self.api = self.repo.api.get_issue(int(id))
        self.title = self.api.title
        self.url = self.api.html_url

    def comment(self, msg):
        self.api.create_comment(msg)
    
    def close(self):
        self.api.edit(state='closed')

    @staticmethod
    def fromURL(repo, url):
        matches = re.findall(r'^https://github.com/{}/issues/(\d+)$'.format(repo.name), url)
        if not matches:
            matches = re.findall(r'^https://pagure.io/{}/issue/(\d+)$'.format(repo.name), url)
            if not matches:
                raise ValueError('Unknown issue link: {}'.format(url))
            
            return PagureIssue(repo, matches[0], url)
        
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


class PagureIssue(Issue):
    def __init__(self, repo, id, url):
        self.repo = repo
        self.id = id
        self.api = self.repo.pagure
        self.title = self.api.issue_info(id)['title']
        self.url = url

    def comment(self, msg):
        self.api.comment_issue(self.id, msg)
    
    def close(self):
        self.api.change_issue_status(self.id, 'Closed', 'Fixed')
