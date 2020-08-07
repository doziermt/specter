import argparse
from datetime import datetime
import os

from specter.commands import CleanList, Command, WebScan, XmlScan
from specter.config import settings
from specter.enums import Applications, Commands
from specter import __version__, exceptions

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

~~~~~~~~~~~~~
Version %s
~~~~~~~~~~~~~

EXECUTION STEPS
---------------

1) tox -e specter -- clean_list
2) tox -e specter -- xml_scan
3) tox -e specter -- web_scan
''' % __version__


def _init_clean_list_parser(subparsers):
    """Argument parser for clean_list operation"""
    clean_list_parser = subparsers.add_parser(
        Commands.CLEAN_LIST.value,
        help='Generate a clean IP address list using nmap')


def _init_xml_scan_parser(subparsers):
    """Argument parser for xml_scan operation"""
    port_scan_parser = subparsers.add_parser(
        Commands.XML_SCAN.value, help='Execute an xml scan using masscan')


def _init_web_scan_parser(subparsers):
    """Argument parser for web_scan operation"""
    web_scan_parser = subparsers.add_parser(
        Commands.WEB_SCAN.value, help='Execute a web scan using eyewitness')


def parse_args(parser):
    args = parser.parse_args()

    command = None
    if args.subcommand == Commands.CLEAN_LIST.value:
        command = CleanList()
    elif args.subcommand == Commands.WEB_SCAN.value:
        command = WebScan()
    elif args.subcommand == Commands.XML_SCAN.value:
        command = XmlScan()
    else:
        # This should be unreachable.
        raise RuntimeError("The sub-command '%s' is not supported" %
                           args.subcommand)
    return command


def build_output_folder_structure(output_directory=os.getcwd()):
    subdirectories = {
        os.path.abspath('%s/output/enumeration' % output_directory),
        os.path.abspath('%s/output/hosts' % output_directory),
        os.path.abspath('%s/output/ports' % output_directory),
        os.path.abspath('%s/output/web_reports/eyewitness' % output_directory),
        os.path.abspath('%s/output/xml' % output_directory),
    }
    for directory in subdirectories:
        if not os.path.isdir(directory):
            print('Creating directories: %s' % directory)
        os.makedirs(directory, exist_ok=True)


def main():
    print(INFO)
    parser = argparse.ArgumentParser(prog='specter')
    subparsers = parser.add_subparsers(title='subcommands',
                                       description='Valid specter subcommands',
                                       dest='subcommand',
                                       required=True)
    _init_web_scan_parser(subparsers)
    _init_xml_scan_parser(subparsers)
    _init_clean_list_parser(subparsers)
    command_to_execute = parse_args(parser)

    build_output_folder_structure()

    try:
        command_to_execute.execute()
    except exceptions.SubprocessExecutionError as e:
        print()
        parser.error(e)
    else:
        parser.exit()


if __name__ == '__main__':
    sys.exit(main())
