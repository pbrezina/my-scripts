# -*- coding: utf-8 -*-

import re

from github import Github

from nutcli.commands import Actor, Command

from utils.actor import MyActor, MySubcommandsActor
from .release_notes import ReleaseNotesActor

class Project(object):
    def __init__(self, config):
        self.name = config.name
        self.github = Github(config.github.token)
        self.repo = self.github.get_repo(config.github.repo)
        self.path = config.local.path

class ProjectActor(MySubcommandsActor):
    def __init__(self, project, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if type(project) is str:
            if not hasattr(self.config.projects, project):
                self.project = None
                return

            self.project = Project(getattr(self.config.projects, project))
        else:
            self.project = Project(project)

    def get_commands(self):
        if self.project is None:
            return []

        return [
            Command('fixed-issues', 'Print fixed issue', FixedIssuesActor(self.project)),
            Command('release-notes', 'Print release notes', ReleaseNotesActor(self.project)),
        ]

class FixedIssuesActor(MyActor):
    def __init__(self, project, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.project = project

    def setup_parser(self, parser):
        parser.add_argument(
            '--from', type=str, action='store', required=True,
            help='Start point reference', dest='since'
        )

        parser.add_argument(
            '--to', type=str, action='store', default='HEAD',
            help='End point reference',
        )

        parser.add_argument(
            '--markdown', '-m', const='md', action='store_const',
            dest='output_format', help='Produce markdown output',
        )

    def __call__(self, since, to, output_format='plain'):
        if output_format is None:
            output_format = 'plain'

        result = self.shell(
            f'git log {since}..{to} | grep -E "{self.project.repo.html_url}/issues/[0-9]+" -o',
            cwd=self.project.path,
            capture_output=True
        )

        for url in sorted(filter(None, list(set(result.stdout.split('\n'))))):
            issue = self.get_issue(url)
            if issue.state.lower() != 'closed':
                continue

            if output_format == 'plain':
                print(f'* #{issue.number} - {issue.title}')
            elif output_format == 'md':
                print(f'* [#{issue.number}]({issue.html_url}) - {issue.title}')
            else:
                raise ValueError(f'Unknown output format: {output_format}')

    def get_issue(self, url):
        matches = re.findall(rf'^{self.project.repo.html_url}/issues/(\d+)$', url)
        if not matches:
            raise ValueError(f'Unknown issue link: {url}')

        return self.project.repo.get_issue(int(matches[0]))
