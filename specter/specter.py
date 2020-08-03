import argparse
import os

from specter.commands import CleanList, Command, WebScan, XmlScan
from specter.config import settings
from specter.enums import Applications, Commands

global INFO

INFO = '''
		SPECTER RECON TOOL 
==================================================
Version 0.1

EXECUTION
sudo python3 <application> <operation> optional flags = -s <site_name.txt> -t <target_list.txt> -e <exclution_list.txt> -h <help>
sudo python3 specter.py clean_list -s ea60test

sudo python3 <application> <operation> optional flags = -s <site_name.txt> -c <clean_target_list.txt>
sudo python3 specter.py port_scan 

sudo python3 <application> <operation> optional flags = -s <site_name.txt> -c <clean_target_list.txt>
sudo python3 specter.py xml_scan 

sudo python3 <application> <operation> optional flags = -s <site_name.txt> -c <clean_target_list.txt>
sudo python3 specter.py web_scan	 
'''


def _init_clean_list_parser(subparsers):
    """Argument parser for clean_list operation"""
    clean_list_parser = subparsers.add_parser(
        Commands.CLEAN_LIST.value, help='Execute a clean list using nmap')


def _init_xml_scan_parser(subparsers):
    """Argument parser for xml_scan operation"""
    port_scan_parser = subparsers.add_parser(
        Commands.XML_SCAN.value, help='Execute a xml scan using masscan')


def _init_web_scan_parser(subparsers):
    """Argument parser for web_scan operation"""
    web_scan_parser = subparsers.add_parser(
        Commands.WEB_SCAN.value, help='Execute a web scan using eyewitness')


def parse_args(parser):
    args = parser.parse_args()
    build_output_folder_structure()

    command = None
    if args.subcommand == Commands.CLEAN_LIST.value:
        command = CleanList()
    elif args.subcommand == Commands.WEB_SCAN.value:
        command = WebScan()
    elif args.subcommand == Commands.XML_SCAN.value:
        command = XmlScan()
    else:
        raise RuntimeError("The sub-command '%s' is not supported" %
                           args.subcommand)

    command.execute()


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
    parser = argparse.ArgumentParser(prog='specter.py')
    subparsers = parser.add_subparsers(title='subcommands',
                                       description='Valid specter subcommands',
                                       dest='subcommand',
                                       required=True)
    _init_web_scan_parser(subparsers)
    _init_xml_scan_parser(subparsers)
    _init_clean_list_parser(subparsers)
    parse_args(parser)


if __name__ == '__main__':
    main()
