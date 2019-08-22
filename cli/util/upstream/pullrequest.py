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
import requests
import tempfile
import textwrap
import subprocess

from github import Github
from util.upstream.author import Author
from util.upstream.label import Label
from util.upstream.issue import Issue
from lib.shell import Shell, ShellScriptError


class PullRequest(object):
    def __init__(self, repo, gh_pr):
        self.repo = repo
        self.api = gh_pr
        self.id = gh_pr.number
        self.title = gh_pr.title
        self.url = gh_pr.html_url

        self._labels = None
        self._targets = None
        self._reviewers = None
        self._patch = None
        self._patchcount = None
        self._issues = None
        
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
        
        matches = re.findall(r'^^(Resolves:\n(?:http.+\n)+)', self.patch, re.MULTILINE)
        issues = set()

        for match in matches:
            for line in match.splitlines():
                if line.startswith('http'):
                    issues.add(Issue.fromURL(self.repo, line))

        self._issues = sorted(list(issues))

        return self._issues
        
    @property
    def targets(self):
        if self._targets is not None:
            return self._targets

        targets = set()
        targets.add(self.api.base.label.split(':')[1])

        for label in self.labels:
            matches = re.findall(r'^branch: (\S+)$', label.name)
            if matches:
                targets.add(matches[0])

        self._targets = sorted(list(targets))
        return self._targets

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
        self.labels.append(label)
    
    def remove_label(self, label):
        if label not in self.labels:
            return
        
        label.remove(self.api)
        self.labels.remove(label)
    
    def push(self, confirm=True, manualcheck=True):
        print(str(self))

        if confirm and not self._confirm('Push the Pull Request?'):
            return
        
        sh = Shell(cwd=self.repo.localdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with tempfile.NamedTemporaryFile() as f:
            f.write(self.patch.encode('utf-8'))
            f.flush()

            # First apply the patch to all target branches
            for target in self.targets:
                sh('git fetch origin')
                sh('git checkout {}'.format(target))
                sh('git branch --set-upstream-to=origin/{target} {target}'.format(target=target))
                sh('git pull --rebase')
                
                try:
                    sh('git am -3 --whitespace=fix {}'.format(f.name))
                except ShellScriptError:
                    sh('git am --abort || :')
                    self._reset_push_state()
                    self.add_label(self.repo.labels.conflict)
                    self.remove_label(self.repo.labels.ready)
                    print('Conflict in {}'.format(target))
                    return

                # Add Reviewed-by tags
                if self.reviewers:
                    sh('git rebase HEAD~{count} -x \'git commit --amend -m"{msg}$(echo -ne \\\\n\\\\n{tags})"\''.format(
                        count=self.patchcount,
                        msg='$(git log --format=%B -n1)',
                        tags='\\\\n'.join(self.tags).replace('<', '\\<').replace('>', '\\>')
                    ))

                # Dry run push
                sh('git push --dry-run origin {}'.format(target))

        if manualcheck and not self._confirm('Dry run succeeded. Continue?'):
            self._reset_push_state()
            return

        # Get push diff
        diff = self._get_push_diff(sh)

        # Push patches
        for target in self.targets:
            sh('git checkout {}'.format(target))
            sh('git push origin {}'.format(target))
            
        # Close PR
        self.comment(diff)
        self.add_label(self.repo.labels.pushed)
        self.remove_label(self.repo.labels.accepted)
        self.remove_label(self.repo.labels.ready)
        self.close()
        
        # Close issues
        for issue in self.issues:
            issue.comment(diff)
            issue.close()
    
    def _reset_push_state(self):
        sh = Shell(cwd=self.repo.localdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for target in self.targets:
            sh('git checkout {}'.format(target))
            sh('git reset --hard origin/{}'.format(target))
    
    def _get_push_diff(self, sh):
        result = sh(
            '''
            for branch in {targets}
            do
                echo "* \`$branch\`"
                format="    * %Cred%H%Creset - %s"
                git log --pretty="format:$format" origin/$branch..$branch
                echo ""
            done
            '''.format(targets=' '.join(['"{}"'.format(x) for x in self.targets]))
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
          - {targets}
          Fixed issues:
          - {issues}
        ''').strip().format(
            id=self.id,
            title=self.title,
            url=self.url,
            reviewed='\n  - '.join([str(x) for x in self.reviewers]),
            targets='\n  - '.join(self.targets),
            issues='\n  - '.join([str(x) for x in self.issues])
            
        )
