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

from nutcli.commands import Command, CommandParser

from utils.actor import MySubcommandsActor
from utils.upstream.repository import Repository
from utils.upstream.upstream import Upstream


class SSSDUpstreamActor(MySubcommandsActor):
    def get_commands(self):
        config = self.config.upstream.sssd
        repo = Repository(
            config.type,
            config.repo,
            config.token,
            config.localdir
        )

        return Upstream.GetCommands(repo)


Commands = Command('sssd', 'SSSD Operations', CommandParser()([
    Command('upstream', 'Upstream operations', SSSDUpstreamActor())
]))
