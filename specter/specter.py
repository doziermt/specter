import argparse
from datetime import datetime
import os

from specter.commands import CleanList, Command, Init, Tree, WebScan, XmlScan
from specter.config import validate_settings
from specter.enums import Applications, Commands
from specter import exceptions

global INFO

INFO = '''
              ...                            
             ;::::;                           
           ;::::; :;                          
         ;:::::'   :;                         
        ;:::::;     ;.                        
       ,:::::'       ;           OOO\         
       ::::::;       ;          OOOOO\        
       ;:::::;       ;         OOOOOOOO       
      ,;::::::;     ;'         / OOOOOOO      
    ;:::::::::`. ,,,;.        /  / DOOOOOO    
  .';:::::::::::::::::;,     /  /     DOOOO   
 ,::::::;::::::;;;;::::;,   /  /        DOOO  
;`::::::`'::::::;;;::::: ,#/  /          DOOO 
:`:::::::`;::::::;;::: ;::#  /            DOOO
::`:::::::`;:::::::: ;::::# /              DOO
`:`:::::::`;:::::: ;::::::#/               DOO
 :::`:::::::`;; ;:::::::::##                OO
 ::::`:::::::`;::::::::;:::#                OO
 `:::::`::::::::::::;'`:;::#                O 
  `:::::`::::::::;' /  / `:#                  
   ::::::`:::::;'  /  /   `#

=================================================
* SPECTER RECON TOOL - KALI LINUX SECURITY TOOL *
=================================================

~~~~~~~~~~~
Version 0.1
~~~~~~~~~~~

EXECUTION STEPS
---------------

0) specter init
1) specter clean_list
2) specter xml_scan
3) specter web_scan
'''


def _init_init_parser(subparsers):
    """Argument parser for initializing specter input/output directory structure and configuration file."""
    init_parser = subparsers.add_parser(
        Commands.INIT.value,
        help='Initialize specter directory structure and config file')


def _init_clean_list_parser(subparsers):
    """Argument parser for clean_list operation."""
    clean_list_parser = subparsers.add_parser(
        Commands.CLEAN_LIST.value, help='Execute a clean list using nmap')


def _init_xml_scan_parser(subparsers):
    """Argument parser for xml_scan operation."""
    port_scan_parser = subparsers.add_parser(
        Commands.XML_SCAN.value, help='Execute a xml scan using masscan')


def _init_web_scan_parser(subparsers):
    """Argument parser for web_scan operation."""
    web_scan_parser = subparsers.add_parser(
        Commands.WEB_SCAN.value, help='Execute a web scan using eyewitness')


def _init_tree_parser(subparsers):
    """Argument parser for pretty-printing the specter directory as a tree."""
    init_parser = subparsers.add_parser(
        Commands.TREE.value,
        help='Pretty prints the specter directory as a tree')


def get_command_from_name(alias):
    command = None

    if alias == Commands.INIT.value:
        command = Init()
    elif alias == Commands.CLEAN_LIST.value:
        command = CleanList()
    elif alias == Commands.TREE.value:
        command = Tree()
    elif alias == Commands.WEB_SCAN.value:
        command = WebScan()
    elif alias == Commands.XML_SCAN.value:
        command = XmlScan()
    else:
        # This should be unreachable.
        raise RuntimeError("The sub-command '%s' is not supported" % alias)

    return command


def load_settings(root_output_directory='.specter'):
    settings_file_path = os.path.join(os.getcwd(), root_output_directory,
                                      'settings.toml')
    validate_settings(settings_file_path=settings_file_path)


def main():
    print(INFO)

    parser = argparse.ArgumentParser(prog='specter')
    subparsers = parser.add_subparsers(title='subcommands',
                                       description='Valid specter subcommands',
                                       dest='subcommand',
                                       required=True)
    _init_init_parser(subparsers)
    _init_clean_list_parser(subparsers)
    _init_xml_scan_parser(subparsers)
    _init_web_scan_parser(subparsers)
    _init_tree_parser(subparsers)

    args = parser.parse_args()
    command = get_command_from_name(args.subcommand)

    if command.__class__ is not Init:
        try:
            load_settings()
        except FileNotFoundError as e:
            parser.error(e)

    try:
        command.execute()
    except exceptions.SubprocessExecutionError as e:
        print()
        parser.error(e)
    else:
        parser.exit()


if __name__ == '__main__':
    sys.exit(main())
