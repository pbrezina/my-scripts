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
import os
import json
import time
import datetime
import bugzilla

from github import Github, GithubException
from util.upstream.pullrequest import PullRequest
from util.upstream.issue import PagureIssue
from lib.command import Actor, CommandList, Command
from math import remainder

class AutoPushActor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo

    def run(self):
        tasks = self.tasklist('autopush')
        for pr in self.get_pull_requests():
            tasks.add(pr.title, self.task_push, pr)

        tasks.run()

    def get_pull_requests(self):
        required = [self.repo.labels.accepted, self.repo.labels.ready]

        pulls = []
        for gh_pr in self.repo.api.get_pulls(state='open'):
            pr = PullRequest(self.repo, gh_pr)
            if all(item in pr.labels for item in required):
                pulls.append(pr)

        return pulls

    def task_push(self, task, pr):
        pr.push(self.repo)


class AutoCloseActor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo

    def run(self):
        issues = self.repo.pagure.list_issues(status='Open', tags='Patch is welcome', per_page=100)
        for issue in issues:
            pissue = PagureIssue(self.repo, issue['id'], None)
            pissue.comment(textwrap.dedent('''
            Thank you for taking time to submit this request for SSSD. Unfortunately this issue was not given priority and the team lacks the capacity to work on it at this time.

            Given that we are unable to fulfill this request I am closing the issue as wontfix.

            If the issue still persist on recent SSSD you can request re-consideration of this decision by reopening this issue. Please provide additional technical details about its importance to you.

            Thank you for understanding.
            '''))
            try:
                pissue.close('wontfix')
            except:
                pass
            print('{} - {} - {}'.format(issue['id'], issue['milestone'], issue['title']))


class ImportReleasesActor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo

    def run(self):
        tags = [
            'sssd-0_2_0',
            'sssd-0_2_1',
            'sssd-0_3_0',
            'sssd-0_3_1',
            'sssd-0_3_2',
            'sssd-0_3_3',
            'sssd-0_4_0',
            'sssd-0_4_1',
            'sssd-0_5_0',
            'sssd-0_6_0',
            'sssd-0_6_1',
            'sssd-0_7_0',
            'sssd-0_7_1',
            'sssd-0_99_0',
            'sssd-0_99_1',
            'sssd-1_0_0',
            'sssd-1_0_1',
            'sssd-1_0_2',
            'sssd-1_0_3',
            'sssd-1_0_4',
            'sssd-1_0_5',
            'sssd-1_0_6',
            'sssd-1_0_7',
            'sssd-1_0_7-2',
            'sssd-1_0_8',
            'sssd-1_0_99',
            'sssd-1_1_0',
            'sssd-1_1_1',
            'sssd-1_1_2',
            'sssd-1_1_91',
            'sssd-1_1_92',
            'sssd-1_2_0',
            'sssd-1_2_1',
            'sssd-1_2_2',
            'sssd-1_2_3',
            'sssd-1_2_4',
            'sssd-1_2_91',
            'sssd-1_3_0',
            'sssd-1_3_1',
            'sssd-1_4_0',
            'sssd-1_4_1',
            'sssd-1_5_0',
            'sssd-1_5_1',
            'sssd-1_5_10',
            'sssd-1_5_11',
            'sssd-1_5_12',
            'sssd-1_5_13',
            'sssd-1_5_14',
            'sssd-1_5_15',
            'sssd-1_5_16',
            'sssd-1_5_17',
            'sssd-1_5_2',
            'sssd-1_5_3',
            'sssd-1_5_4',
            'sssd-1_5_5',
            'sssd-1_5_6',
            'sssd-1_5_6_1',
            'sssd-1_5_7',
            'sssd-1_5_8',
            'sssd-1_5_9',
            'sssd-1_6_0',
            'sssd-1_6_1',
            'sssd-1_6_2',
            'sssd-1_6_3',
            'sssd-1_6_4',
            'sssd-1_7_0',
            'sssd-1_7_91',
            'sssd-1_7_92',
            'sssd-1_7_93',
            'sssd-1_8_0',
            'sssd-1_8_0_beta1',
            'sssd-1_8_0_beta2',
            'sssd-1_8_0_beta3',
            'sssd-1_8_1',
            'sssd-1_8_2',
            'sssd-1_8_3',
            'sssd-1_8_4',
            'sssd-1_8_5',
            'sssd-1_8_6',
            'sssd-1_8_91',
            'sssd-1_8_92',
            'sssd-1_8_93',
            'sssd-1_8_94',
            'sssd-1_8_95',
            'sssd-1_8_96',
            'sssd-1_8_97',
            'sssd-1_8_98',
            'sssd-1_9_0',
            'sssd-1_9_0_beta1',
            'sssd-1_9_0_beta2',
            'sssd-1_9_0_beta3',
            'sssd-1_9_0_beta4',
            'sssd-1_9_0_beta5',
            'sssd-1_9_0_beta6',
            'sssd-1_9_0_beta7',
            'sssd-1_9_0_rc1',
            'sssd-1_9_1',
            'sssd-1_9_2',
            'sssd-1_9_3',
            'sssd-1_9_4',
            'sssd-1_9_5',
            'sssd-1_9_6',
            'sssd-1_9_7',
            'sssd-1_9_91',
            'sssd-1_9_92',
            'sssd-1_9_93',
            'sssd-1_9_94',
            'sssd-1_10_0',
            'sssd-1_10_1',
            'sssd-1_10_90',
            'sssd-1_10_92',
            'sssd-1_10_alpha1',
            'sssd-1_10_beta1',
            'sssd-1_10_beta2',
            'sssd-1_11_0',
            'sssd-1_11_0_beta1',
            'sssd-1_11_0_beta2',
            'sssd-1_11_1',
            'sssd-1_11_2',
            'sssd-1_11_3',
            'sssd-1_11_4',
            'sssd-1_11_5',
            'sssd-1_11_5_1',
            'sssd-1_11_6',
            'sssd-1_11_7',
            'sssd-1_11_8',
            'sssd-1_11_90',
            'sssd-1_11_91',
            'sssd-1_12_0',
            'sssd-1_12_0_beta1',
            'sssd-1_12_0_beta2',
            'sssd-1_12_1',
            'sssd-1_12_2',
            'sssd-1_12_3',
            'sssd-1_12_4',
            'sssd-1_12_5',
            'sssd-1_12_90',
            'sssd-1_13_0',
            'sssd-1_13_0_alpha',
            'sssd-1_13_1',
            'sssd-1_13_2',
            'sssd-1_13_3',
            'sssd-1_13_4',
            'sssd-1_13_90',
            'sssd-1_13_91',
            'sssd-1_14_0',
            'sssd-1_14_0_alpha1',
            'sssd-1_14_0_beta1',
            'sssd-1_14_1',
            'sssd-1_14_2',
            'sssd-1_15_0',
            'sssd-1_15_1',
            'sssd-1_15_2',
            'sssd-1_15_3',
            'sssd-1_16_0',
            'sssd-1_16_1',
            'sssd-1_16_2',
            'sssd-1_16_3',
            'sssd-1_16_4',
            'sssd-1_16_5',
            'sssd-2_0_0',
            'sssd-2_1_0',
            'sssd-2_2_0',
            'sssd-2_2_1',
            'sssd-2_2_2',
            'sssd-2_2_3',
        ]

        for tag in tags:
            relnote = None
            relname = tag.replace('_', '.')
            try:
                path = re.sub(r'^sssd-(.*)$', '/home/pbrezina/workspace/sssd_docs/users/relnotes/md/notes_\\1.md', tag)
                with open(path) as f:
                    relnote = f.read()
            except:
                pass

            self.message('New release: {} / {} / {}'.format(relname, tag, relnote is not None))

            try:
                self.repo.api.create_git_release(
                    tag=tag,
                    name=relname,
                    message=relnote if relnote is not None else '',
                    draft=False,
                    prerelease=False
                )
            except:
                raise


class DeleteReleasesActor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo

    def run(self):
        for release in self.repo.api.get_releases():
            self.message('Deleting: {}'.format(release.title))
            release.delete_release()

class UploadTarballActor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo

    def run(self):
        for release in self.repo.api.get_releases():

            if not "alpha" in release.title and not "beta" in release.title:
                continue

            tarball=f'/home/pbrezina/Downloads/tarball/{release.title}.tar.gz'
            asc=f'/home/pbrezina/Downloads/tarball/{release.title}.tar.gz.asc'
            sha=f'/home/pbrezina/Downloads/tarball/{release.title}.tar.gz.sha256sum'



            self.message('Updating: {}'.format(release.title))

            if not os.path.exists(tarball):
                continue

            release.upload_asset(
                path=tarball,
                name=f'{release.title}.tar.gz'
            )

            release.upload_asset(
                path=asc,
                name=f'{release.title}.tar.gz.asc'
            )

            release.upload_asset(
                path=sha,
                name=f'{release.title}.tar.gz.sha256sum'
            )


class FetchIssuesActor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo

    def setup_parser(self, parser):
        parser.add_argument(
            '-o', action='store', type=str, dest='out',
            help='Output file'
        )

    def run(self, args):
        api = self.repo.pagure
        issues = []
        for page in range(1,42):
            issues += api.list_issues(per_page=100, page=page, status='all')

        issues.reverse()
        with open(args.out, "w") as f:
            f.write(json.dumps(issues))

        print(f"Written {len(issues)} issues")


class ProbeIssuesActor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo

    def setup_parser(self, parser):
        parser.add_argument(
            '-i', action='store', type=str, dest='issues',
            help='Issues file'
        )

    def run(self, args):
        with open(args.issues) as f:
            issues = json.load(f)

        tags = set()
        status = set()
        closestatus = set()
        milestones = set()
        assignees = set()
        bugs = set()
        for issue in issues:
            for tag in issue['tags']:
                tags.add(tag)

            status.add(issue['status'])

            if issue['status'] == "Closed":
                closestatus.add(issue['close_status'])
            milestones.add(issue['milestone'])
            if issue['assignee']:
                assignees.add(issue['assignee']['name'])

            bugs = bugs.union(self.get_bugs(issue))

        print('Tags:')
        for tag in tags:
            print('- ' + tag)

        print('Status:')
        for s in status:
            print('- ' + s)

        print('Close status:')
        for s in closestatus:
            print(f"- {s}")

        print('Milestones:')
        for s in milestones:
            print(f"- {s}")

        print('Assignees:')
        for s in assignees:
            print(f"'{s}':'https://github.com/{s}")
        return
        print(f'Bugs: {len(bugs)}')
        for s in bugs:
            print(f"- {s}")

    def get_bugs(self, issue):
        bugs = set()
        for field in issue['custom_fields']:
            if field['name'] == 'rhbz':
                bug = field['value']
                if not bug or bug.strip() == "0":
                    continue

                bug = bug.replace('[https://bugzilla.redhat.com/show_bug.cgi?id=1622109 #1622109]', '1622109')
                bug = bug.replace('https://bugzilla.redhat.com/show_bug.cgi?id=', '')
                bug = bug.replace(', ', ' ')
                bug = bug.replace(',', ' ')
                for id in filter(None, bug.split(' ')):
                    if id.strip() == "todo":
                        continue
                    bugs.add(f"https://bugzilla.redhat.com/show_bug.cgi?id={id}")

        return bugs


class CloneToGithubActor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo

    def setup_parser(self, parser):
        parser.add_argument(
            '-i', action='store', type=str, dest='issues',
            help='Issues file'
        )

        parser.add_argument(
            '-o', action='store', type=str, dest='out',
            help='Output file'
        )

    def run(self, args):
        with open(args.issues) as f:
            issues = json.load(f)

        start = self.fix_last_issues(args, issues)
        with open(args.out, 'a') as f:
            remaining = self.check_rate(0)
            for issue in issues[start:]:
                self.check_rate(remaining)
                self.clone_issue(f, issue)
                remaining -= 2

    def test_issue(self, issues, id):
        for issue in issues:
             if issue['id'] == id:
                 print(self.format_description(issue))
                 return

    def fix_last_issues(self, args, issues):
        with open(args.out) as f:
            lines = f.readlines()

        if not lines:
            return 0

        (issueid, ghissueid) = lines[-1].split(':')
        issueid = int(issueid)
        ghissueid = int(ghissueid)

        # Find last stored issue
        start = 0
        for issue in issues:
            start += 1
            if issue['id'] == issueid:
                break

        # Check last stored issue
        issue = issues[start - 1]
        if issue['status'] == 'Closed':
            ghissue = self.repo.api.get_issue(ghissueid)
            if ghissue.state != "closed":
                ghissue.edit(state='closed')

        # Check if there exist one more issue than stored
        try:
            ghissue = self.repo.api.get_issue(ghissueid + 1)
            start += 1
            issue = issues[start - 1]
            if issue['status'] == 'Closed':
                if ghissue.state != "closed":
                    ghissue.edit(state='closed')

            with open(args.out, 'a') as f:
                f.write(f"{issue['id']}:{ghissue.number}\n")
                f.flush()

        except GithubException as e:
            if int(e.status) != 404:
                raise

        return start

    def check_rate(self, remaining):
        if remaining >= 100:
            return remaining

        limit = self.repo.github.get_rate_limit()
        remaining = limit.core.remaining
        if remaining >= 100:
            return remaining

        # Wait for renewal
        resetts = int(limit.core.reset.timestamp())
        sleeptime = resetts - int(datetime.datetime.now().timestamp())
        self.message(f"Sleeping till {limit.core.reset} + 10 seconds")
        time.sleep(sleeptime + 10)

        limit = self.repo.github.get_rate_limit()
        remaining = limit.core.remaining
        return remaining


    def clone_issue(self, f, issue):
        self.message('Cloning: {}'.format(issue['id']))
        ghissue = self.repo.api.create_issue(
            title=issue['title'],
            body=self.format_description(issue),
            assignees=self.get_assignees(issue),
            labels=self.get_closed_labels(issue) + self.get_labels(issue)
        )
        f.write(f"{issue['id']}:{ghissue.number}\n")
        f.flush()

        if issue['status'] == 'Closed':
            ghissue.edit(state='closed')

    def get_assignees(self, issue):
        users = {
            'mzidek':'mzidek-gh',
            'atikhonov':'alexey-tikhonov',
            'jhrozek':'jhrozek',
            'pbrezina':'pbrezina',
            'nkondras':'spbnick',
            'ppolawsk':'elkoniu',
            'avisiedo':'avisiedo',
            'sbose':'sumit-bose'
        }

        return []

        if issue['assignee'] is None:
            return []

        if not issue['assignee']['name'] in users:
            return []

        return [users[issue['assignee']['name']]]

    def get_closed_labels(self, issue):
        if issue['status'] != "Closed":
            return []

        labels = {
            'fixed': 'Closed: Fixed',
            'invalid': 'Closed: Not a bug',
            'wontfix': "Closed: Won't fix",
            'duplicate': 'Closed: Duplicate',
            'worksforme': 'Closed: Works for me'
        }

        if issue['close_status'] is None:
            return []

        return [labels[issue['close_status'].lower()]]

    def get_labels(self, issue):
        table = {
            'New hire task': 'New hire task',
            'breaks compatibility': 'Breaks compatibility',
            'Next milestone': 'Next milestone',
            'tests': 'Tests',
            'regression': 'Regression',
            'Future milestone': 'Future milestone',
            'easyfix': 'Easy to fix',
            'KCM': 'KCM',
            'bugzilla': 'Bugzilla',
            'RFE': 'RFE'
        }

        labels = []
        for tag in issue['tags']:
            if tag in table:
                labels.append(table[tag])

        if len(self.get_bugs(issue)) > 0 and 'Bugzilla' not in labels:
            labels.append('Bugzilla')

        return labels

    def get_bugs(self, issue):
        bugs = set()
        for field in issue['custom_fields']:
            if field['name'] == 'rhbz':
                bug = field['value']

                if not bug or bug.strip() == "0":
                    continue

                bug = bug.replace('[https://bugzilla.redhat.com/show_bug.cgi?id=1622109 #1622109]', '1622109')
                bug = bug.replace('https://bugzilla.redhat.com/show_bug.cgi?id=', '')
                bug = bug.replace(', ', ' ')
                bug = bug.replace(',', ' ')
                for id in filter(None, bug.split(' ')):
                    if id.strip() == "todo":
                        continue
                    bugs.add(f"https://bugzilla.redhat.com/show_bug.cgi?id={id}")

        return bugs

    def format_description(self, issue):
        out = ""
        out += f"Cloned from Pagure issue: https://pagure.io/SSSD/sssd/issue/{issue['id']}\n"
        out += f"- Created at {self.format_time(issue['date_created'])} by {self.user(issue['user'])}\n"

        if issue['status'] == "Closed":
            if issue['closed_at'] is not None:
                out += f"- Closed at {self.format_time(issue['closed_at'])} as {issue['close_status']}\n"
            else:
                out += f"- Closed as {issue['close_status']}\n"

        if issue['assignee']:
            out += f"- Assigned to {self.user(issue['assignee'])}\n"
        else:
            out += f"- Assigned to nobody\n"

        bugs = self.get_bugs(issue)
        if bugs:
            out += f"- Associated bugzillas\n"
            for bug in bugs:
                out += f"  - {bug}\n"

        out += "\n---\n\n"
        out += issue['content'].strip()

        if issue['comments']:
            out += "\n\n### Comments\n"

            for comment in issue['comments']:
                out += "\n---\n\n"
                out += f"**Comment from {self.user(comment['user'])} at {self.comment_time(issue, comment)}**\n\n"
                out += comment['comment'].strip()
                out += "\n"

        return out

    def format_time(self, timestamp):
        dt = datetime.datetime.fromtimestamp(int(timestamp))

        return dt.strftime("%Y-%m-%d %H:%M:%S")

    def user(self, user):
        return f"[{user['name']}](https://pagure.io/user/{user['name']})"

    def comment_time(self, issue, comment):
        return f"[{self.format_time(comment['date_created'])}](https://pagure.io/SSSD/sssd/issue/{issue['id']}#{comment['id']})"


class UpdatePagureActor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo

    def setup_parser(self, parser):
        parser.add_argument(
            '-i', action='store', type=str, dest='issues',
            help='Issues file'
        )

        parser.add_argument(
            '-o', action='store', type=str, dest='out',
            help='Output file'
        )

    def run(self, args):
        with open(args.issues) as f:
            issues = json.load(f)

        with open(args.out) as f:
            lines = f.readlines()
            ghmap = {}
            for line in lines:
                (pid, gid) = line.split(':')
                ghmap[int(pid)] = int(gid)

        i = 0
        for issue in issues:
            if issue['id'] == 3731:
                break
            i += 1

        for issue in issues[i:]:
            self.update_issue(issue, ghmap[issue['id']])

    def update_issue(self, issue, ghid):
        self.message(f"Updating {issue['id']} to https://github.com/SSSD/sssd/issues/{ghid}")

        msg = textwrap.dedent(f"""
        SSSD is moving from Pagure to Github. This means that new issues and pull requests
        will be accepted only in [SSSD's github repository](https://github.com/SSSD/sssd).

        This issue has been cloned to Github and is available here:
        - https://github.com/SSSD/sssd/issues/{ghid}

        If you want to receive further updates on the issue, please navigate [to the github issue](https://github.com/SSSD/sssd/issues/{ghid})
        and click on `subscribe` button.

        Thank you for understanding. We apologize for all inconvenience.
        """).strip()
        self.repo.pagure.comment_issue(issue['id'], msg)

        if issue['status'] != 'Closed':
            self.repo.pagure.change_issue_status(issue['id'], 'Closed', 'cloned-to-github')


class UpdateBugzillaActor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo
        self.bz = bugzilla.Bugzilla("bugzilla.redhat.com", api_key="cvvg8rWB599FQfaYFt9ZsMRljcg10L5fRX5JULPs")
        #self.bz = bzapi = bugzilla.Bugzilla("partner-bugzilla.redhat.com", api_key="tBHzONrZgKydr8NYvqkX6Nx2fQHdxgXACyesFohJ")

    def setup_parser(self, parser):
        parser.add_argument(
            '-i', action='store', type=str, dest='issues',
            help='Issues file'
        )

        parser.add_argument(
            '-o', action='store', type=str, dest='out',
            help='Output file'
        )

        parser.add_argument(
            '-s', action='store', type=int, dest='start', default=0,
            help='Start index'
        )

    def run(self, args):
        with open(args.issues) as f:
            issues = json.load(f)

        with open(args.out) as f:
            lines = f.readlines()
            ghmap = {}
            for line in lines:
                (pid, gid) = line.split(':')
                ghmap[int(pid)] = int(gid)

        bzbugs = self.get_bz_bugs()
        for idx, issue in enumerate(issues[args.start:]):
            bugs = self.get_issue_bugs(issue)
            for id in bugs:
                self.message(f"{idx+args.start}: https://bugzilla.redhat.com/show_bug.cgi?id={id} https://pagure.io/SSSD/sssd/issue/{issue['id']} https://github.com/SSSD/sssd/issues/{ghmap[int(issue['id'])]}")
                bug = self.find_bz_bug(id, bzbugs)
                if bug:
                    self.update_bz(id, int(issue['id']), ghmap[int(issue['id'])])

    def find_bz_bug(self, id, bzbugs):
        for bug in bzbugs:
            if int(bug.id) == int(id):
                return bug

        return None

    def get_issue_bugs(self, issue):
        bugs = set()
        for field in issue['custom_fields']:
            if field['name'] == 'rhbz':
                bug = field['value']
                if not bug or bug.strip() == "0":
                    continue
                bug = bug.replace('[https://bugzilla.redhat.com/show_bug.cgi?id=1622109 #1622109]', '1622109')
                bug = bug.replace('https://bugzilla.redhat.com/show_bug.cgi?id=', '')
                bug = bug.replace(', ', ' ')
                bug = bug.replace(',', ' ')
                for id in filter(None, bug.split(' ')):
                    if id.strip() == "todo":
                        continue
                    bugs.add(int(id))

        return bugs

    def get_bz_bugs(self):
        self.message('Querying bugs')
        sssdquery = self.bz.build_query(
            component="sssd",
            include_fields=["devel_whiteboard", "external_bugs", "component", "product", "summary"]
        )

        dlquery = self.bz.build_query(
            component="ding-libs",
            include_fields=["devel_whiteboard", "external_bugs", "component", "product", "summary"]
        )

        bugs = self.bz.query(sssdquery) +self.bz.query(dlquery)
        self.message(f"Found {len(bugs)} bugs in bugzilla")

        return bugs

    def update_bz(self, bzid, pid, ghid):
        bug = self.bz.getbug(bzid)
        whiteboard = bug.devel_whiteboard.strip()
        if f'SSSD {pid}' in whiteboard:
            whiteboard = whiteboard.replace(f'SSSD {pid}', f'SSSD {ghid}')
        else:
            if whiteboard:
                whiteboard = whiteboard + f', SSSD {ghid}'
            else:
                whiteboard = f'SSSD {ghid}'
        print(f"{whiteboard}")

        update = self.bz.build_update(devel_whiteboard=whiteboard)
        self.bz.update_bugs([bzid], update)
        self.bz.add_external_tracker(bzid, f"SSSD/sssd/issues/{ghid}", ext_type_id=131)


class UpdateBugzilla2Actor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo
        self.bz = bugzilla.Bugzilla("bugzilla.redhat.com", api_key="cvvg8rWB599FQfaYFt9ZsMRljcg10L5fRX5JULPs")
        #self.bz = bzapi = bugzilla.Bugzilla("partner-bugzilla.redhat.com", api_key="tBHzONrZgKydr8NYvqkX6Nx2fQHdxgXACyesFohJ")

    def setup_parser(self, parser):
        parser.add_argument(
            '-i', action='store', type=str, dest='issues',
            help='Issues file'
        )

        parser.add_argument(
            '-o', action='store', type=str, dest='out',
            help='Output file'
        )

        parser.add_argument(
            '-s', action='store', type=int, dest='start', default=0,
            help='Start index'
        )

    def run(self, args):
        with open(args.issues) as f:
            issues = json.load(f)

        with open(args.out) as f:
            lines = f.readlines()
            ghmap = {}
            for line in lines:
                (pid, gid) = line.split(':')
                ghmap[int(pid)] = int(gid)

        bzbugs = self.get_bz_bugs()
        for bug in bzbugs:
            for issueid in re.findall('SSSD (\d+)', bug.devel_whiteboard):
                found = False
                for tracker in bug.external_bugs:
                    if tracker['type']['id'] == 131:
                        found = True
                if found:
                    break

                if int(issueid) not in ghmap:
                    self.message(f"https://bugzilla.redhat.com/show_bug.cgi?id={bug.id} -")
                    self.remove(bug.id, int(issueid))
                else:
                    self.message(f"https://bugzilla.redhat.com/show_bug.cgi?id={bug.id} https://pagure.io/SSSD/sssd/issue/{issueid} https://github.com/SSSD/sssd/issues/{ghmap[int(issueid)]}")
                    self.update_bz(bug.id, int(issueid), ghmap[int(issueid)])

    def get_bz_bugs(self):
        self.message('Querying bugs')
        sssdquery = self.bz.build_query(
            component="sssd",
            include_fields=["devel_whiteboard", "external_bugs", "component", "product", "summary"]
        )

        dlquery = self.bz.build_query(
            component="ding-libs",
            include_fields=["devel_whiteboard", "external_bugs", "component", "product", "summary"]
        )

        bugs = self.bz.query(sssdquery) +self.bz.query(dlquery)
        self.message(f"Found {len(bugs)} bugs in bugzilla")

        return bugs

    def remove(self, bzid, pid):
        bug = self.bz.getbug(bzid)
        whiteboard = bug.devel_whiteboard.strip()
        if f'SSSD {pid}' in whiteboard:
            whiteboard = whiteboard.replace(f'SSSD {pid}', '')
        print(f"{whiteboard}")

        update = self.bz.build_update(devel_whiteboard=whiteboard)
        self.bz.update_bugs([bzid], update)

    def update_bz(self, bzid, pid, ghid):
        bug = self.bz.getbug(bzid)
        whiteboard = bug.devel_whiteboard.strip()
        if f'SSSD {pid}' in whiteboard:
            whiteboard = whiteboard.replace(f'SSSD {pid}', f'SSSD {ghid}')
        else:
            if whiteboard:
                whiteboard = whiteboard + f', SSSD {ghid}'
            else:
                whiteboard = f'SSSD {ghid}'
        print(f"{whiteboard}")

        update = self.bz.build_update(devel_whiteboard=whiteboard)
        self.bz.update_bugs([bzid], update)
        self.bz.add_external_tracker(bzid, f"SSSD/sssd/issues/{ghid}", ext_type_id=131)


class UpdateAssigneeActor(Actor):
    def __init__(self, repo):
        super().__init__()
        self.repo = repo

    def setup_parser(self, parser):
        parser.add_argument(
            '-i', action='store', type=str, dest='issues',
            help='Issues file'
        )

        parser.add_argument(
            '-o', action='store', type=str, dest='out',
            help='Output file'
        )

    def run(self, args):
        with open(args.issues) as f:
            issues = json.load(f)

        with open(args.out) as f:
            lines = f.readlines()
            ghmap = {}
            for line in lines:
                (pid, gid) = line.split(':')
                ghmap[int(pid)] = int(gid)

        for issue in issues:
            self.update_issue(issue, ghmap[issue['id']])

    def update_issue(self, issue, ghid):
        assignees = self.get_assignees(issue)
        if not assignees:
            return

        self.message(f'Updating https://github.com/SSSD/sssd/issues/{ghid} {assignees}')
        ghissue = self.repo.api.get_issue(ghid)
        ghissue.add_to_assignees(assignees[0])

    def get_assignees(self, issue):
        users = {
            'mzidek':'mzidek-gh',
            'atikhonov':'alexey-tikhonov',
            'jhrozek':'jhrozek',
            'pbrezina':'pbrezina',
            'nkondras':'spbnick',
            'ppolawsk':'elkoniu',
            'avisiedo':'avisiedo',
            'sbose':'sumit-bose'
        }

        users = {
            'abbra': 'abbra',
            'pcech': 'celestian',
            'spbnick': 'spbnick',
            'nkondras': 'spbnick'

        }

        users = {
            'lslebodn': 'lslebodn'
        }

        if issue['assignee'] is None:
            return []

        if not issue['assignee']['name'] in users:
            return []

        return [users[issue['assignee']['name']]]

# 1 Fetch issues DONE
# 2 Clone to github DONE
# 3 Close issues on github DONE
# 4 Update tags DONE
# 5 Update bugzillas
# 6 Update Pagure DONE


class Upstream(object):
    @staticmethod
    def GetCommands(repo):
        return CommandList([
            Command('autopush', 'Push acked pull requests', AutoPushActor(repo)),
            Command('autoclose', 'Close issues', AutoCloseActor(repo)),
            Command('import-releases', 'Import releases', ImportReleasesActor(repo)),
            Command('delete-releases', 'Delete releases', DeleteReleasesActor(repo)),
            Command('upload-tarball', 'Upload tarball', UploadTarballActor(repo)),
            Command('fetch-issues', 'Fetch issues', FetchIssuesActor(repo)),
            Command('probe-issues', 'Probe issues', ProbeIssuesActor(repo)),
            Command('clone-issues', 'Migrate issues', CloneToGithubActor(repo)),
            Command('update-pagure', 'Update issues', UpdatePagureActor(repo)),
            Command('update-bugzilla', 'Update bugs', UpdateBugzillaActor(repo)),
            Command('update-bugzilla2', 'Update bugs', UpdateBugzilla2Actor(repo)),
            Command('update-assignee', 'Update bugs', UpdateAssigneeActor(repo)),
        ])
