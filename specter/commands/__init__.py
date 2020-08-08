from specter.commands.abstract import Command
from specter.commands.clean_list import CleanList
from specter.commands.init import Init
from specter.commands.tree import Tree
from specter.commands.web_scan import WebScan
from specter.commands.xml_scan import XmlScan

__all__ = (Command.__class__.__name__, CleanList.__class__.__name__,
           Init.__class__.__name__, Tree.__class__.__name__,
           WebScan.__class__.__name__, XmlScan.__class__.__name__)
