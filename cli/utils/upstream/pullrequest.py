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
import tempfile
import textwrap

import requests
from nutcli.shell import Shell, ShellError

from utils.upstream.author import Author
from utils.upstream.issue import Issue
from utils.upstream.label import Label


class PullRequest(object):
    def __init__(self, repo, gh_pr):
        self.repo = repo
        self.api = gh_pr
        self.id = gh_pr.number
        self.title = gh_pr.title
        self.url = gh_pr.html_url

        self._labels = None
        self._target = None
        self._backport_to = None
        self._reviewers = None
        self._patch = None
        self._patchcount = None
        self._issues = None

        self.shell = Shell(
            cwd=self.repo.localdir,
            capture_output=True
        )

    @property
    def labels(self):
        if self._labels is not None:
            return self._labels

        self._labels = [Label(x.name, x.color, x.description) for x in self.api.get_labels()]
        return self._labels

    @property
    def patch(self):
        if self._patch is not None:
            return self._patch

        response = requests.get(self.api.patch_url)
        self._patch = response.content.decode('utf-8')
        return self._patch

    @property
    def patchcount(self):
        if self._patchcount is not None:
            return self._patchcount

        matches = re.search(r'^Subject: \[PATCH \d+/(\d+)\]', self.patch, re.MULTILINE)
        self._patchcount = 1 if not matches else matches.group(1)
        return self._patchcount

    @property
    def issues(self):
        if self._issues is not None:
            return self._issues

        resolves = re.findall(r'^Resolves: *\n?(?:http\S+\n?)+', self.patch, re.MULTILINE)
        issues = set()

        for match in resolves:
            urls = re.findall(r'(http\S+)', match)
            for url in urls:
                issues.add(Issue.fromURL(self.repo, url))

        self._issues = sorted(list(issues))

        return self._issues

    @property
    def target(self):
        if self._target is not None:
            return self._target

        self._target = self.api.base.label.split(':')[1]
        return self._target

    @property
    def backport_to(self):
        if self._backport_to is not None:
            return self._backport_to

        targets = set()
        for label in self.labels:
            matches = re.findall(r'^branch: (\S+)$', label.name)
            if matches:
                targets.add(matches[0])

        self._backport_to = sorted(list(targets))
        return self._backport_to

    @property
    def reviewers(self):
        if self._reviewers is not None:
            return self._reviewers

        reviewers = set()
        for assignee in self.api.assignees:
            author = Author(assignee.login)
            reviewers.add(author)

        self._reviewers = sorted(list(reviewers))
        return self._reviewers

    @property
    def tags(self):
        tags = []
        for author in self.reviewers:
            tags.append('Reviewed-by: {} <{}>'.format(author.name, author.email))

        return tags

    def comment(self, msg):
        self.api.create_issue_comment(msg)

    def close(self):
        self.api.as_issue().edit(state='closed')

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

    def push(self, confirm=True, manualcheck=True):
        print(str(self))

        if confirm and not self._confirm('Push the Pull Request?'):
            return

        with tempfile.NamedTemporaryFile() as f:
            f.write(self.patch.encode('utf-8'))
            f.flush()

            # First apply patch to target branch
            commits = self._apply_path(f.name, self.target)
            if not commits:
                return

            # First apply the patch to all target branches
            for target in self.backport_to:
                self._cherry_pick(commits, target)

        # Get push diff
        comment = f'Pushed PR: {self.url}\n\n{self._get_push_diff()}'
        print(comment)

        if manualcheck and not self._confirm('Dry run succeeded. Continue?'):
            self._reset_push_state()
            return

        # Push patches
        for target in [self.target] + self.backport_to:
            self.shell('git checkout {}'.format(target))
            self.shell('git push origin {}'.format(target))

        # Close PR
        self.comment(comment)
        self.add_label(self.repo.labels.pushed)
        self.remove_label(self.repo.labels.accepted)
        self.remove_label(self.repo.labels.ready)
        self.close()

        # Close issues
        for issue in self.issues:
            issue.comment(comment)
            issue.close()
            issue.add_label(self.repo.labels.fixed)

    def _rebase(self, branch):
        self.shell('git fetch origin')
        self.shell('git checkout {}'.format(branch))
        self.shell('git branch --set-upstream-to=origin/{branch} {branch}'.format(branch=branch))
        self.shell('git pull --rebase')

    def _apply_path(self, patch, target):
        self._rebase(target)

        try:
            self.shell('git am -3 --whitespace=fix {}'.format(patch))
        except ShellError:
            self.shell('git am --abort || :')
            self._reset_push_state()
            self.remove_label(self.repo.labels.ready)
            print('Conflict in {}'.format(target))
            return None

        # Add Reviewed-by tags
        if self.reviewers:
            self.shell('git rebase HEAD~{count} -x \'git commit --amend -m"{msg}$(echo -ne \\\\n\\\\n{tags})"\''.format(
                count=self.patchcount,
                msg='$(git log --format=%B -n1)',
                tags='\\\\n'.join(self.tags).replace('<', '\\<').replace('>', '\\>')
            ))

        # Dry run push
        self.shell('git push --dry-run origin {}'.format(target))

        # Get list of commits
        result = self.shell('git log --pretty="format:%H" origin/{0}..{0}'.format(target))
        commits = result.stdout.decode('utf-8').split()
        commits.reverse()

        return commits

    def _cherry_pick(self, commits, target):
        self._rebase(target)

        try:
            self.shell('git cherry-pick -x {}'.format(' '.join(commits)))
        except ShellError:
            self.shell('git cherry-pick --abort || :')
            self._reset_push_state()
            self.remove_label(self.repo.labels.ready)
            print('Conflict in {}'.format(target))
            return False

        # Dry run push
        self.shell('git push --dry-run origin {}'.format(target))

        return True

    def _reset_push_state(self):
        for branch in [self.target] + self.backport_to:
            self.shell('git checkout {}'.format(branch))
            self.shell('git reset --hard origin/{}'.format(branch))

    def _get_push_diff(self):
        result = self.shell(
            '''
            for branch in {targets}
            do
                echo "* \\`$branch\\`"
                format="    * %Cred%H%Creset - %s"
                git log --pretty="format:$format" origin/$branch..$branch
                echo ""
            done
            '''.format(targets=' '.join(['"{}"'.format(x) for x in [self.target] + self.backport_to]))
        )

        return result.stdout.decode('utf-8')

    def _confirm(self, msg):
        answer = ''
        while answer not in ['y', 'n']:
            answer = input('{} [y/n] '.format(msg)).lower()

        if answer == 'n':
            return False

        return True

    def __str__(self):
        return textwrap.dedent('''
        PR {id}: {title}
          URL: {url}
          Reviewed by:
          - {reviewed}
          Targeting:
          - {target}
          Backport to:
          - {backports}
          Fixed issues:
          - {issues}
        ''').strip().format(
            id=self.id,
            title=self.title,
            url=self.url,
            reviewed='\n  - '.join([str(x) for x in self.reviewers]),
            target=self.target,
            backports='\n  - '.join(self.backport_to),
            issues='\n  - '.join([str(x) for x in self.issues])

        )
