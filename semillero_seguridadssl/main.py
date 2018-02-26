__all__ = [
    'main',
]

import click
from click_shell import shell

from commands.metasploit_commands import *
from commands.nmap_commands import NmapCommands
from commands.openvas_commands import *


@shell(prompt='SSL>> ', hist_file='./.click_hs')
def cli():
    pass


cli.add_command(NmapCommands.nmap)
cli.add_command(MetasploitCommands.metasploit)
cli.add_command(ExploitCommands.exploit)
cli.add_command(PayloadCommands.payload)
cli.add_command(OpenvasCommands.openvas)

banner = """
     ____                                          __               __
    /\  _`\                                 __    /\ \             /\ \ 
    \ \,\L\_\     __     __   __  __  _ __ /\_\   \_\ \     __     \_\ \ 
     \/_\__ \   /'__`\ /'_ `\/\ \/\ \/\`'__\/\ \  /'_` \  /'__`\   /'_` \ 
       /\ \L\ \/\  __//\ \L\ \ \ \_\ \ \ \/ \ \ \/\ \L\ \/\ \L\.\_/\ \L\ \ 
       \ `\____\ \____\ \____ \ \____/\ \_\  \ \_\ \___,_\ \__/.\_\ \___,_\ 
        \/_____/\/____/\/___L\ \/___/  \/_/   \/_/\/__,_ /\/__/\/_/\/__,_ /
                         /\____/
                         \_/__/
                           ____    ____    __
                          /\  _`\ /\  _`\ /\ \ 
                          \ \,\L\_\ \,\L\_\ \ \ 
                           \/_\__ \\\\/_\__ \\\\ \ \  __
                             /\ \L\ \/\ \L\ \ \ \L\ \ 
                             \ `\____\ `\____\ \____/
                              \/_____/\/_____/\/___/
"""


def main():
    click.secho(banner, fg='blue', bold=True)
    cli()


if __name__ == "__main__":
    main()
