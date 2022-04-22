# -*- coding: utf-8 -*-

import os

from nutcli.commands import Actor, Command, CommandParser


class CIActor(Actor):
    def __call__(self, command):
        self.shell(f'sudo make -C "$MY_WORKSPACE/sssd-ci-containers" {command}')

class CIUpActor(CIActor):
    def setup_parser(self, parser):
        super().setup_parser(parser)

        parser.add_argument(
            '--tag', type=str, action='store', default='latest', help='Tag',
        )

        parser.add_argument(
            '--registry', type=str, action='store', default='quay.io/sssd', help='Registry',
        )

        parser.add_argument(
            '--limit', type=str, action='store', default='', help='Limit',
        )

    def __call__(self, tag, registry, limit):
        super().__call__(f'up TAG="{tag}" REGISTRY="{registry}" LIMIT="{limit}"')


class CIStopActor(CIActor):
    def __call__(self):
        super().__call__('stop')


class CIDownActor(CIActor):
    def __call__(self):
        super().__call__('down')

class CIShellActor(CIActor):
    def setup_parser(self, parser):
        parser.add_argument(
            '--shell', type=str, nargs='?', action='store', default='/bin/tmux', help='Shell',
        )

        parser.add_argument(
            'container', type=str, choices=['client', 'ipa', 'ldap', 'samba'], default='client'
        )

    def __call__(self, shell, container):
        self.shell(f'sudo podman exec -u ci -it "{container}" "{shell}"')



class CIRemoveImageActor(CIActor):
    def setup_parser(self, parser):
        super().setup_parser(parser)

        parser.add_argument(
            '--tag', type=str, action='store', default='latest', help='Tag',
        )

        parser.add_argument(
            '--registry', type=str, action='store', default='quay.io/sssd', help='Registry',
        )


    def __call__(self, tag, registry):
        images = [
            'ci-client-devel',
            'ci-client',
            'ci-dns',
            'ci-ipa',
            'ci-ldap',
            'ci-samba',
        ]

        for image in images:
            self.shell(f'sudo podman image rm --force "{registry}/{image}:{tag}"')


Commands = Command('ci', 'SSSD CI Containers', CommandParser()([
    Command('up', 'Start containers', CIUpActor()),
    Command('stop', 'Stop containers', CIStopActor()),
    Command('down', 'Destroy containers', CIDownActor()),
    Command('sh', 'Get shell', CIShellActor()),
    Command('remove', 'Remove images', CIRemoveImageActor()),
]))
