# -*- coding: utf-8 -*-

import click
import mmbot as mmb

@click.command()
def main(args=None):
    """Console script for MaliciousMacroBot"""
    click.echo("Replace this message by putting your code into "
               "mmbot.cli.main")
    click.echo("See click documentation at http://click.pocoo.org/")


if __name__ == "__main__":
    mymacrobot = mmb.MaliciousMacroBot()
    main()
