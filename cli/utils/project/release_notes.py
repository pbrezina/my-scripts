# -*- coding: utf-8 -*-

import re
import textwrap

from utils.actor import MyActor


class ReleaseNotesActor(MyActor):
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
            '--version', type=str, action='store', required=True,
            help='New release version', dest='version'
        )

        parser.add_argument(
            '--markdown', '-m', const='md', action='store_const',
            dest='output_format', help='Produce markdown output',
        )

    def __call__(self, since, to, version, output_format='plain'):
        if output_format is None:
            output_format = 'plain'

        if output_format not in ['plain', 'md']:
            raise ValueError(f'Unsupported format: {output_format}')

        result = self.shell(
            f'git log {since}..{to}',
            cwd=self.project.path,
            capture_output=True
        )

        relnotes = [
            ReleaseNote('relnote', 'General information'),
            ReleaseNote('feature', 'New features'),
            ReleaseNote('fixes', 'Important fixes'),
            ReleaseNote('packaging', 'Packaging changes'),
            ReleaseNote('config', 'Configuration changes'),
        ]

        renderer = getattr(self, f'_render_{output_format}')
        output = renderer(version)
        for rn in relnotes:
            notes = rn.findall(result.stdout)
            render = rn.render(notes, output_format)
            if not render:
                continue

            output.append('')
            output.append(rn.render(notes, output_format))

        print('\n'.join(output).strip())

    def _render_plain(self, version):
        return [f'{self.project.name} {version} Release Notes', '', 'Highlights']

    def _render_md(self, version):
        return [f'# {self.project.name} {version} Release Notes', '', '## Highlights']


class ReleaseNote(object):
    def __init__(self, tag, title):
        self.tag = tag
        self.title = title
        self.notes = []

    def findall(self, log):
        matches = re.findall(rf'^ *:{self.tag}:((?:(?!(?:^ *:\w+:| *$)).*\n)+)', log, re.MULTILINE)
        if not matches:
            return []

        notes = []
        for m in matches:
            note = ' '.join([x.strip() for x in m.split('\n')])
            notes.append(note)

        return notes

    def render(self, notes, output_format):
        if output_format not in ['plain', 'md']:
            raise ValueError(f'Unsupported format: {output_format}')

        renderer = getattr(self, f'_render_{output_format}')
        return renderer(notes)

    def _render_plain(self, notes):
        if not notes:
            return ''

        notes = [f'- {x}' for x in notes]

        if self.title is None:
            return '\n'.join(notes)

        return '\n'.join([self.title, *notes])

    def _render_md(self, notes):
        if not notes:
            return ''

        notes = [f'* {x}' for x in notes]

        if self.title is None:
            return '\n'.join(notes)

        return '\n'.join([f'### {self.title}', '', *notes])
