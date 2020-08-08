from specter.commands import Command
from specter.utils import print_tree


class Tree(Command):
    """Pretty-prints the .specter directory as a tree."""
    APPLICATION = None

    def __init__(self):
        super().__init__()

    def execute(self):
        print_tree()
