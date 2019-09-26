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
import textwrap

from github import Github
from lib.command import Command, CommandList, CommandParser
from util.actor import MyActor, MyCommandParserActor
from util.upstream.upstream import Upstream
from util.upstream.repository import Repository


class SSSDAutoPushActor(MyActor):
    def __init__(self):
        super().__init__()

    def run(self, args, argv=None):
        gh = Github(self.config.tokens.github)
        labels = WellKnownLabels()
        upstream = Upstream(
            gh.get_repo('pbrezina/apitest'),
            '/home/pbrezina/workspace/sssd-origin',
            labels
        )
        upstream.autopush(self, [labels.accepted, labels.ready])


class SSSDUpstreamActor(MyCommandParserActor):
    def subcommands(self):
        config = self.config.upstream.sssd
        repo = Repository(config.type, config.repo, config.token, config.localdir, config.pagure)
        return Upstream.GetCommands(repo)

#Commands = Command('sssd', 'SSSD Operations', CommandParser([
#    Command('upstream', 'Upstream operations', CommandParser([
#        Command('autopush', 'Push acked pull requests', SSSDAutoPushActor)
#    ]))
#]))

Commands = Command('sssd', 'SSSD Operations', CommandParser([
    Command('upstream', 'Upstream operations', SSSDUpstreamActor)
]))
