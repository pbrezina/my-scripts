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
import shutil
import textwrap
import tempfile
import requests
import subprocess

from github import Github
from util.upstream.pullrequest import PullRequest

class Upstream(object):
    def __init__(self, repo, repodir, labels):
        self.repo = repo
        self.repodir = repodir
        self.labels = labels

    def get_pull_request(self, id):
        pr = self.repo.get_pull(id)
        return PullRequest(self.repo, pr)

    def get_pull_requests(self, required_labels, state='open'):
        pulls = []
        for gh_pr in self.repo.get_pulls(state=state):
            pr = PullRequest(self.repo, gh_pr)
            if all(item in pr.labels for item in required_labels):
                pulls.append(pr)

        return pulls
    
    def autopush(self, command, required_labels):
        def task_push(task, pr):
            pr.push(self.repodir, self.labels)
        
        tasks = command.tasklist('autopush')
        for pr in self.get_pull_requests(required_labels=required_labels):
            tasks.add(pr.title, task_push, pr)

        tasks.run()
