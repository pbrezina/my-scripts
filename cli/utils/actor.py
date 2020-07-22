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

import nutcli
import yaml


class MyActor(nutcli.commands.Actor):
    def __init__(self,  *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.project_dir = os.path.abspath(
            os.path.dirname(os.path.realpath(__file__)) + '/../..'
        )
        self.config = self.__load_config(self.project_dir + '/my.yml')

    def __load_config(self, config):
        with open(config) as f:
            data = yaml.safe_load(f)

        merged = {}
        if type(data) is list:
            for item in data:
                merged.update(item)
        else:
            merged = data

        return nutcli.utils.dict_to_namespace(merged)


class MySubcommandsActor(nutcli.commands.SubcommandsActor, MyActor):
    pass
