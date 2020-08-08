from specter.commands import Command
from specter.utils import print_tree


class Tree(Command):
    """Pretty-prints the specter_workdir directory as a tree."""
    APPLICATION = None

    def __init__(self):
        super().__init__()

    def execute(self):
        print_tree()
