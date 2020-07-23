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

from nutcli.commands import Actor, Command
from nutcli.tasks import Task, TaskList

from utils.upstream.pullrequest import PullRequest


class AutoPushActor(Actor):
    def __init__(self, repo, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.repo = repo

    def __call__(self):
        tasks = TaskList('autopush')
        for pr in self.get_pull_requests():
            tasks.append(Task(pr.title)(self.task_push, pr))

        tasks.execute()

    def get_pull_requests(self):
        required = [self.repo.labels.accepted, self.repo.labels.ready]

        pulls = []
        for gh_pr in self.repo.api.get_pulls(state='open'):
            pr = PullRequest(self.repo, gh_pr)
            if all(item in pr.labels for item in required):
                pulls.append(pr)

        return pulls

    def task_push(self, pr):
        pr.push(self.repo)


class Upstream(object):
    @staticmethod
    def GetCommands(repo):
        return [
            Command('autopush', 'Push acked pull requests', AutoPushActor(repo)),
        ]
