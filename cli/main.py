#!/bin/python3
# -*- coding: utf-8 -*-

import argparse
import sys

import argcomplete
import nutcli.commands
import nutcli.runner

import commands.projects
import commands.sssd


class Program:
    def setup_parser(self):
        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawTextHelpFormatter
        )

        nutcli.commands.CommandParser()([
            nutcli.commands.CommandGroup('Project Managers')([
                commands.projects.Commands,
            ]),
            nutcli.commands.CommandGroup('Old')([
                commands.sssd.Commands,
            ])
        ]).setup_parser(parser)
        argcomplete.autocomplete(parser)

        return parser

    def main(self, argv):
        parser = self.setup_parser()
        runner = nutcli.runner.Runner('my', parser).setup_parser()

        args = runner.parse_args(argv)
        runner.default_logger()
        return runner.execute(args)


if __name__ == "__main__":
    program = Program()
    sys.exit(program.main(sys.argv[1:]))
