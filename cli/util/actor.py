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

import os
import yaml

from argparse import Namespace
from lib.command import Actor, CommandParserActor


class MyActor(Actor):
    def __init__(self):
        super().__init__()

        self.root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + '/../..')
        self.config = self._load_config(self.root_dir + '/my.yml')

    def _load_config(self, config):
        with open(config) as f:
            data = yaml.safe_load(f)

        return self._to_namespace(data[0])

    def _to_namespace(self, d):
        if type(d) != dict:
            return d
        
        ns = Namespace()
        for key, value in d.items():
            setattr(ns, key, self._to_namespace(value))
        
        return ns


class MyCommandParserActor(CommandParserActor, MyActor):
    pass
    



