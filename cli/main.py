#!/bin/python3
# -*- coding: utf-8 -*-

import argcomplete
import argparse
import sys
import textwrap

# Command Actors
import commands.sssd as sssd

from lib.command import CommandParser, CommandGroup, Runner


class Program:
    def setup_parser(self):
        commands = CommandParser([
            sssd.Commands
        ])

        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawTextHelpFormatter
        )

        commands.setup_parser(parser)
        argcomplete.autocomplete(parser)

        return parser

    def main(self, argv):
        return Runner('my').execute(self.setup_parser(), argv)


if __name__ == "__main__":
    program = Program()
    sys.exit(program.main(sys.argv[1:]))
