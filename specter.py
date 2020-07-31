import abc
import argparse
import datetime
from enum import Enum
import ipaddress
import os
import re
import subprocess
import csv
import string
import mmap
import time
import xml.etree.ElementTree as ET

global IS_DEBUG_ENABLED
global INFO
global SPECTER_INPUT_EXCLUDE_FILE_PATH
global SPECTER_INPUT_TARGET_FILE_PATH
global TIMESTAMP

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

SPECTER_INPUT_EXCLUDE_FILE_PATH = 'input/ip_lists/exclude.txt'
SPECTER_INPUT_SITE_NAME_FILE_PATH = 'input/ip_lists/site_name.txt'
SPECTER_INPUT_TARGET_FILE_PATH = 'input/ip_lists/target.txt'
SPECTER_INPUT_OPERATION_DIR_PATH = 'input/operation'
SPECTER_OUTPUT_ENUMERATION_DIR_PATH = 'output/enumeration'
TIMESTAMP = '{:%Y-%m-%d_%H-%M-%S}'.format(
    datetime.datetime.now())  #use this time stamp on all fields


class Commands(Enum):
    PORT_SCAN = 'port_scan'
    CLEAN_LIST = 'clean_list'
    XML_SCAN = 'xml_scan'
    WEB_SCAN = 'web_scan'


class Applications(Enum):
    MASSCAN = 'masscan'
    NMAP = 'nmap'
    EYEWITNESS = 'eyewitness'
    AQUATONE = 'aquatone'


class OperationFiles(Enum):
    COMMON_PORTS = os.path.join(SPECTER_INPUT_OPERATION_DIR_PATH,
                                'common_ports.csv')
    PORT_SCAN = os.path.join(SPECTER_INPUT_OPERATION_DIR_PATH, 'scan.csv')


class ValidationError(Exception):
    """Raised by instances of `Command` whenever CLI-provided inputs fail internal validation."""
    pass


class Command(abc.ABC):
    """Abstract base class that all commands should inherit from."""
    @abc.abstractmethod
    def execute(self):
        """Method for executing the CLI applications associated with this `Command`."""
        pass


class Web_Scan(Command):  #web_scan operation class
    def __init__(self, clean_target_list_file, sitename):
        parameter_value_map = {}
        filename = os.path.abspath(OperationFiles.PORT_SCAN.value)
        with open(filename, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile, delimiter=",")
            for row in reader:
                parameter_value_map[
                    row['PARAMETER'].lower()] = row['VALUE_EXECUTED']

        self.application = parameter_value_map['web_application']
        self.scan_rate = parameter_value_map['jitter'] or 0
        self.scan_type = parameter_value_map['web_ports']
        self.sitename = sitename

        if clean_target_list_file == None:
            clean_target_list = parameter_value_map['clean_target_web']

        if clean_target_list_file != None:
            clean_target_list = clean_target_list_file

        if not clean_target_list:
            raise ValidationError(
                'The "CLEAN_TARGET_LIST" parameter is required')
        if not os.path.isfile(os.path.abspath(clean_target_list)):
            raise FileNotFoundError(
                'Could not find file "%s", please create it and try again' %
                clean_target_list)
        self.clean_target_list = os.path.abspath(clean_target_list)

    def execute(
        self
    ):  # Executes the web_scan command, currently only supports eyewitness

        web_port = str(self.scan_type)
        web_port = web_port.replace("-", ",")

        if self.application == Applications.EYEWITNESS.value:
            web_command = str(self.application + ' --web --add-http-ports ' +
                              web_port + ' --add-https-ports ' + web_port +
                              ' --no-prompt --threads 4 --jitter ' +
                              self.scan_rate + ' -f ' +
                              self.clean_target_list +
                              ' -d output/web_reports/eyewitness')

        if self.application == Applications.AQUATONE.value:
            #web_command = str(self.application+' ')
            raise NotImplementedError(
                "You Broke Specter, Aquatone is not implimented yet, try again!!!"
            )

        subprocess.call(web_command, shell=True, universal_newlines=True)

        print()
        print(web_command)  #Prints out the web_scan command that is running
        print()
        print(
            "Web Scan Complete, output located in specter/output/web_reports/eyewitness/ "
        )
        print()


class Port_Scan(Command):  # port_scan operation class
    def __init__(self, clean_target_list_file, sitename):
        parameter_value_map = {}
        filename = os.path.abspath(OperationFiles.PORT_SCAN.value)
        with open(filename, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile, delimiter=",")
            for row in reader:
                parameter_value_map[
                    row['PARAMETER'].lower()] = row['VALUE_EXECUTED']

        self.timestamp = '{:%Y-%m-%d_%H-%M-%S}'.format(datetime.datetime.now())
        self.application = parameter_value_map['application']
        self.interface = parameter_value_map['interface']
        self.scan_rate = parameter_value_map['scan_rate'] or 3000
        self.ip = parameter_value_map['masscan_ip']
        self.sitename = sitename

        if clean_target_list_file == None:
            clean_target_list = parameter_value_map['clean_target_list']

        if clean_target_list_file != None:
            clean_target_list = clean_target_list_file

        if not clean_target_list:
            raise ValidationError(
                'The "CLEAN_TARGET_LIST" parameter is required')
        if not os.path.isfile(os.path.abspath(clean_target_list)):
            raise FileNotFoundError(
                'Could not find file "%s", please create it and try again' %
                clean_target_list)
        self.clean_target_list = os.path.abspath(clean_target_list)

    def execute(self):  # Executes the masscan execution call
        if self.application == Applications.MASSCAN.value:

            command = str(self.application +
                          ' --max-retries=1 --banners --source-ip ' + self.ip +
                          ' --source-port 61000 --open -e ' + self.interface +
                          " -p " + self.ports + ' -iL ' +
                          self.clean_target_list + " --rate=" +
                          self.scan_rate + " -oG " +
                          self.enumeration_output_file)

        print('Running "port_scan" operation')
        print()
        print(command)  #prints out masscan execution command
        subprocess.call(command, shell=True, universal_newlines=True)
        print()
        print("Port Scan Complete, output located in specter/output/ ")
        print()

        #creates default target file for web_scan with IPs that have web ports open -- so be sorted to another file and passed to web_scan
        subprocess.call(
            'grep "443/open/tcp" ' + self.enumeration_output_file +
            ' | cut -d " " -f 2 | cut -c1-15 | sort -u > input/ip_lists/web_scan_ip2.txt',
            shell=True,
            universal_newlines=False)
        subprocess.call(
            'grep "80/open/tcp" ' + self.enumeration_output_file +
            ' | cut -d " " -f 2 | cut -c1-15 | sort -u >> input/ip_lists/web_scan_ip2.txt',
            shell=True,
            universal_newlines=False)
        subprocess.call(
            'grep "8000/open/tcp" ' + self.enumeration_output_file +
            ' | cut -d " " -f 2 | cut -c1-15 | sort -u >> input/ip_lists/web_scan_ip2.txt',
            shell=True,
            universal_newlines=False)
        subprocess.call(
            'grep "8080/open/tcp" ' + self.enumeration_output_file +
            ' | cut -d " " -f 2 | cut -c1-15 | sort -u >> input/ip_lists/web_scan_ip2.txt',
            shell=True,
            universal_newlines=False)
        subprocess.call(
            'grep "8443/open/tcp" ' + self.enumeration_output_file +
            ' | cut -d " " -f 2 | cut -c1-15 | sort -u >> input/ip_lists/web_scan_ip2.txt',
            shell=True,
            universal_newlines=False)

        #creats PORT.txt files with IPs
        #subprocess.call(str('grep "Ports:" '+self.enumeration_output_file+' | cut -d " " -f 4 | cut -d "/" -f1 | sort -u -k 1nbr > output/ports/ports.txt'), shell=True, universal_newlines=True)
        subprocess.call(str(
            'grep "Ports:" ' + self.enumeration_output_file +
            ' | cut -d " " -f 4 | cut -d "/" -f1 | sort -u > output/ports/ports.txt'
        ),
                        shell=True,
                        universal_newlines=True)
        port_list = open("output/ports/ports.txt")
        for i in (port_list):
            port_output_command = str(
                'grep "' + str(i.rstrip()) + '/open/tcp" ' +
                self.enumeration_output_file +
                ' | cut -d " " -f 2 | cut -c1-15 | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n > output/ports/'
                + str(i.rstrip()) + '_.txt ')
            subprocess.call(port_output_command,
                            shell=True,
                            universal_newlines=False)

        #creats IP.txt files with open ports
        subprocess.call(
            'grep "Host" ' + self.enumeration_output_file +
            ' | cut -d ":" -f2 | cut -d " " -f2 | sort -u -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n > output/hosts/hostIP.txt',
            shell=True,
            universal_newlines=True)
        ip_list = open("output/hosts/hostIP.txt")
        for i in (ip_list):
            ip_output_command = 'grep "' + str(
                i.rstrip()
            ) + ' ()" ' + self.enumeration_output_file + ' | cut -d ":" -f3-15 | sort -u  > output/hosts/' + str(
                i.rstrip()) + '.txt'
            subprocess.call(ip_output_command,
                            shell=True,
                            universal_newlines=False)

        #cleans output/hosts directory of unused or empy data files
        subprocess.call(
            'sudo sort -u -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n input/ip_lists/web_scan_ip2.txt | uniq > input/ip_lists/web_scan_ip.txt',
            shell=True,
            universal_newlines=False)
        os.remove('input/ip_lists/web_scan_ip2.txt')
        subprocess.call('sudo find output/hosts -size 0 -delete',
                        shell=True,
                        universal_newlines=True)
        subprocess.call('sudo find output/ports -size 0 -delete',
                        shell=True,
                        universal_newlines=True)
        #time.sleep(5)

        #capture XML data to import into MSF db_import   //  possibly own operation // import string from file
        #command = str("nmap -sS -sV -O -Pn -p1-2000 -iL input/ip_lists/clean_target_list.txt -oX output/xml/nmap_"+TIMESTAMP+".xml")
        #subprocess.call(command, shell=True, universal_newlines=True)

    @property
    def ports(self):
        with open(os.path.abspath(OperationFiles.COMMON_PORTS.value),
                  'r') as csvfile:
            return csvfile.readline().strip()

    @property
    def enumeration_output_file(self):
        return self._get_output_filename('enumeration')

    def _get_output_filename(self, dirname, extra_label=None, ext='txt'):
        global TIMESTAMP

        if self.sitename.endswith(os.extsep + ext):
            filename, ext = os.path.splitext(self.sitename)
            if extra_label:
                sitename = '_'.join([filename, extra_label, TIMESTAMP, ext])
            else:
                sitename = '_'.join([filename, TIMESTAMP, ext])
        else:
            if extra_label:
                sitename = '_'.join([self.sitename, extra_label, TIMESTAMP
                                     ]) + os.extsep + ext
            else:
                sitename = '_'.join([self.sitename, TIMESTAMP
                                     ]) + os.extsep + ext
        return os.path.abspath(os.path.join('output', dirname, sitename))


class Xml_Scan(Command):  # port_scan operation class
    WEB_PORTS_TO_SCAN = (
        ("tcp", "443"),
        ("tcp", "80"),
        ("tcp", "8000"),
        ("tcp", "8080"),
        ("tcp", "8443"),
    )

    def __init__(self, clean_target_list_file, sitename):
        parameter_value_map = {}
        filename = os.path.abspath(OperationFiles.PORT_SCAN.value)
        with open(filename, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile, delimiter=",")
            for row in reader:
                parameter_value_map[
                    row['PARAMETER'].lower()] = row['VALUE_EXECUTED']

        self.timestamp = '{:%Y-%m-%d_%H-%M-%S}'.format(datetime.datetime.now())
        self.application = parameter_value_map['application']
        self.interface = parameter_value_map['interface']
        self.scan_rate = parameter_value_map['scan_rate'] or 3000
        self.ip = parameter_value_map['masscan_ip']
        self.sitename = sitename

        if clean_target_list_file == None:
            clean_target_list = parameter_value_map['clean_target_list']

        if clean_target_list_file != None:
            clean_target_list = clean_target_list_file

        if not clean_target_list:
            raise ValidationError(
                'The "CLEAN_TARGET_LIST" parameter is required')
        if not os.path.isfile(os.path.abspath(clean_target_list)):
            raise FileNotFoundError(
                'Could not find file "%s", please create it and try again' %
                clean_target_list)
        self.clean_target_list = os.path.abspath(clean_target_list)

    def parse_masscan_xml_for_ip_addresses(self, filename, target_protocol,
                                           target_portid):
        ip_addresses = set()

        tree = ET.parse(filename)
        root = tree.getroot()
        hosts = root.findall("host")

        for host in hosts:
            ports = host.find("ports").findall("port")
            for port in ports:
                protocol = port.attrib.get("protocol")
                portid = port.attrib.get("portid")
                if protocol == target_protocol and portid == target_portid:
                    address = host.find("address")
                    ip_address = address.attrib.get("addr")
                    ip_addresses.add(ipaddress.ip_address(ip_address))

        return ip_addresses

    def parse_masscan_xml_for_port_ip_address_mapping(self, filename):
        port_ip_address_map = dict()

        tree = ET.parse(filename)
        root = tree.getroot()
        hosts = root.findall("host")

        for host in hosts:
            ports = host.find("ports").findall("port")
            for port in ports:
                portid = port.attrib.get("portid")
                port_ip_address_map.setdefault(portid, set())

                address = host.find("address")
                ip_address = address.attrib.get("addr")
                port_ip_address_map[portid].add(
                    ipaddress.ip_address(ip_address))

        return port_ip_address_map

    def parse_masscan_xml_for_ip_address_port_mapping(self, filename):
        ip_address_port_map = dict()

        tree = ET.parse(filename)
        root = tree.getroot()
        hosts = root.findall("host")

        for host in hosts:
            address = host.find("address")
            ip_address = address.attrib.get("addr")

            ip_address_port_map.setdefault(ip_address, list())

            port = host.find("ports").find("port")
            portid = port.attrib.get("portid")
            state = port.find("state").attrib.get("state")
            reason = port.find("state").attrib.get("reason")
            reason_ttl = port.find("state").attrib.get("reason_ttl")
            service = port.find("service")
            service_name = service.attrib.get(
                "name") if service is not None else None
            service_banner = service.attrib.get(
                "banner") if service is not None else None

            all_fields = [
                portid, state, reason, reason_ttl, service_name, service_banner
            ]
            valid_fields = [field for field in all_fields if field is not None]
            line = ",".join(valid_fields)
            ip_address_port_map[ip_address].append(line)

        for ip_address in ip_address_port_map:
            ip_address_port_map[ip_address].sort(key=lambda x: x.split(",")[0])

        print(ip_address_port_map)
        return ip_address_port_map

    def write_output_to_file(self, filename, ip_addresses):
        if isinstance(ip_addresses, set):
            ip_addresses = list(ip_addresses)

        ip_addresses.sort()

        with open(filename, 'w') as out:
            out.writelines("\n".join([str(x) for x in ip_addresses]))

    def execute(self):  # Executes the masscan execution call
        if self.application == Applications.MASSCAN.value:

            command = str(self.application +
                          ' --max-retries=1 --banners --source-ip ' + self.ip +
                          ' --source-port 61000 --open -e ' + self.interface +
                          " -p " + self.ports + ' -iL ' +
                          self.clean_target_list + " --rate=" +
                          self.scan_rate + " -oX output/xml/masscan.xml")

        print('Running "xml_scan" operation', sep='\n\n')
        print(command, sep='\n\n')
        subprocess.call(command, shell=True, universal_newlines=True)
        print("XML Scan Complete, output located in specter/output/")

        all_ip_addresses = set()
        for (protocol, portid) in self.WEB_PORTS_TO_SCAN:
            ip_addresses = self.parse_masscan_xml_for_ip_addresses(
                "output/xml/masscan.xml", protocol, portid)
            all_ip_addresses = all_ip_addresses.union(ip_addresses)
        self.write_output_to_file("input/ip_lists/web_scan_ip.txt",
                                  all_ip_addresses)

        port_ip_addresses_map = self.parse_masscan_xml_for_port_ip_address_mapping(
            "output/xml/masscan.xml")
        for (port, ip_addresses) in port_ip_addresses_map.items():
            self.write_output_to_file("output/ports/%s.txt" % port,
                                      ip_addresses)

        ip_addresses_port_map = self.parse_masscan_xml_for_ip_address_port_mapping(
            "output/xml/masscan.xml")
        for (ip_address, output) in ip_addresses_port_map.items():
            self.write_output_to_file("output/hosts/%s.txt" % ip_address,
                                      output)

    @property
    def ports(self):
        with open(os.path.abspath(OperationFiles.COMMON_PORTS.value),
                  'r') as csvfile:
            return csvfile.readline().strip()

    @property
    def enumeration_output_file(self):
        return self._get_output_filename('enumeration')

    def _get_output_filename(self, dirname, extra_label=None, ext='txt'):
        global TIMESTAMP

        if self.sitename.endswith(os.extsep + ext):
            filename, ext = os.path.splitext(self.sitename)
            if extra_label:
                sitename = '_'.join([filename, extra_label, TIMESTAMP, ext])
            else:
                sitename = '_'.join([filename, TIMESTAMP, ext])
        else:
            if extra_label:
                sitename = '_'.join([self.sitename, extra_label, TIMESTAMP
                                     ]) + os.extsep + ext
            else:
                sitename = '_'.join([self.sitename, TIMESTAMP
                                     ]) + os.extsep + ext
        return os.path.abspath(os.path.join('output', dirname, sitename))


class Clean_List(Command):
    def __init__(
            self, output_directory, target_list_file, exclude_list_file,
            sitename):  #reads in variables of clean_target_list.txt output

        self._timestamp = '{:%Y-%m-%d_%H-%M-%S}'.format(
            datetime.datetime.now())
        self._output_directory = output_directory
        self._target_list_file = target_list_file
        self._exclude_list_file = exclude_list_file
        self._sitename = sitename

    def execute(
            self
    ):  #Creates command for execution of clean_target_list.txt output

        command = [
            "nmap", "-sL", "-n", "-iL",
            os.path.abspath(self._target_list_file.name), "--excludefile",
            os.path.abspath(self._exclude_list_file.name), "-oN",
            self.clean_target_list_output_file
        ]

        output = subprocess.run(
            command, capture_output=True
        )  #executes the nmap call to update and create a time stamped clean target list

        if output.returncode != 0:
            raise RuntimeError(
                'Failed to generate clean target list, nmap stderr: %s' %
                output.stderr)

        relevant_output = output.stdout.decode("utf-8").split("\n")[1:-2]
        formatted_output = [
            line.split(' ')[-1] + '\n' for line in relevant_output
        ]

        with open(self.clean_target_list_output_file, 'w') as outfile:
            outfile.writelines(formatted_output)
            print("clean target list saved to: " +
                  self.clean_target_list_output_file)

        with open("input/ip_lists/clean_target_list.txt", 'w') as outfile:
            outfile.writelines(formatted_output)
            print()
            print(
                "clean target list saved to: /specter/input/ip_lists/clean_target_list.txt"
            )
            print()

    @property
    def clean_target_list_output_file(self):  #creates output file name
        return self._get_output_filename('clean_target_lists',
                                         extra_label='clean_ip_list')

    def _get_output_filename(self, dirname, extra_label=None, ext='txt'):
        if self._sitename.endswith(os.extsep + ext):
            filename, ext = os.path.splitext(self._sitename)
            if extra_label:
                sitename = '_'.join(
                    [filename, extra_label, self._timestamp, ext])
            else:
                sitename = '_'.join([filename, self._timestamp, ext])
        else:
            if extra_label:
                sitename = '_'.join([
                    self._sitename, extra_label, self._timestamp
                ]) + os.extsep + ext
            else:
                sitename = '_'.join([self._sitename, self._timestamp
                                     ]) + os.extsep + ext
        return os.path.abspath(os.path.join('input', 'ip_lists', sitename))


def _init_clean_list_parser(
        subparsers):  #argument parser for clean_list operation
    clean_list_parser = subparsers.add_parser(
        Commands.CLEAN_LIST.value, help='Execute a clean list using nmap')
    clean_list_parser.add_argument(
        '--output-directory',
        '-o',
        dest='output_directory',
        metavar='DIRECTORY',
        type=str,
        nargs='?',
        default='.',
        help='Optional Output directory where clean_target_list will output to'
    )
    clean_list_parser.add_argument(
        '--target-list',
        '-t',
        dest='target_list_file',
        metavar='FILE',
        type=argparse.FileType(mode='r'),
        nargs='?',
        help='Optional relative or absolute path to the clean target list file'
    )
    clean_list_parser.add_argument(
        '--exclude-list',
        '-e',
        dest='exclude_list_file',
        metavar='FILE',
        type=argparse.FileType(mode='r'),
        nargs='?',
        help='Optional relative or absolute path to the exclude list file')
    clean_list_parser.add_argument(
        '--sitename',
        '-s',
        dest='sitename',
        type=str,
        nargs='?',
        help='The clean_target_list site name added to timestamp .')


def _init_port_scan_parser(
        subparsers):  #argument parser for port_scan operation
    port_scan_parser = subparsers.add_parser(
        Commands.PORT_SCAN.value, help='Execute a port scan using masscan')
    port_scan_parser.add_argument(
        '--clean_target_list_file',
        '-c',
        dest='clean_target_list_file',
        type=str,
        nargs='?',
        help='Optional relative or absolute path to the clean target list file'
    )
    port_scan_parser.add_argument(
        '--sitename',
        '-s',
        dest='sitename',
        type=str,
        nargs='?',
        help='The clean_target_list site name added to timestamp .')


def _init_xml_scan_parser(
        subparsers):  #argument parser for port_scan operation
    port_scan_parser = subparsers.add_parser(
        Commands.XML_SCAN.value, help='Execute a xml scan using masscan')
    port_scan_parser.add_argument(
        '--clean_target_list_file',
        '-c',
        dest='clean_target_list_file',
        type=str,
        nargs='?',
        help='Optional relative or absolute path to the clean target list file'
    )
    port_scan_parser.add_argument(
        '--sitename',
        '-s',
        dest='sitename',
        type=str,
        nargs='?',
        help='The clean_target_list site name added to timestamp .')


def _init_web_scan_parser(subparsers):  #argument parser for web_scan operation
    web_scan_parser = subparsers.add_parser(
        Commands.WEB_SCAN.value, help='Execute a web scan using eyewitness')
    web_scan_parser.add_argument(
        '--clean_target_list_file',
        '-c',
        dest='clean_target_list_file',
        type=str,
        nargs='?',
        help='Optional relative or absolute path to the clean target list file'
    )
    web_scan_parser.add_argument(
        '--sitename',
        '-s',
        dest='sitename',
        type=str,
        nargs='?',
        help='The clean_target_list site name added to timestamp .')


def build_output_folder_structure(
    output_directory
):  #not called currently // creates the default output directories
    subdirectories = {
        os.path.abspath('%s/output/enumeration' % output_directory),
        os.path.abspath('%s/output/hosts' % output_directory),
        os.path.abspath('%s/output/pots' % output_directory),
        os.path.abspath('%s/output/web_reports/eyewitness' % output_directory),
        os.path.abspath('%s/output/xml' % output_directory),
    }
    for directory in subdirectories:
        if not os.path.isdir(directory):
            print_debug('Creating directories: %s' % directory)
        os.makedirs(directory, exist_ok=True)


def print_debug(message):

    print('[DEBUG] %s' % message)


def parse_args(parser):
    args = parser.parse_args()
    #build_output_folder_structure(arg.output_directory)  # calls build_output_folder_structure() method
    command = None
    try:
        if args.subcommand == Commands.WEB_SCAN.value:
            command = Web_Scan(
                clean_target_list_file=args.clean_target_list_file,
                sitename=args.sitename
                or open("input/ip_lists/site_name.txt").readline().strip(),
            )
        if args.subcommand == Commands.CLEAN_LIST.value:
            command = Clean_List(
                output_directory=args.output_directory or 'specter',
                target_list_file=args.target_list_file
                or open("input/ip_lists/target.txt"),
                exclude_list_file=args.exclude_list_file
                or open("input/ip_lists/exclude.txt"),
                sitename=args.sitename
                or open("input/ip_lists/site_name.txt").readline().strip(),
            )
        if args.subcommand == Commands.PORT_SCAN.value:
            command = Port_Scan(
                clean_target_list_file=args.clean_target_list_file,
                sitename=args.sitename
                or open("input/ip_lists/site_name.txt").readline().strip(),
            )
        if args.subcommand == Commands.XML_SCAN.value:
            command = Xml_Scan(
                clean_target_list_file=args.clean_target_list_file,
                sitename=args.sitename
                or open("input/ip_lists/site_name.txt").readline().strip(),
            )

    except (RuntimeError, ValidationError) as e:
        parser.error(e)
    command.execute()


def main():

    print(INFO)
    parser = argparse.ArgumentParser(prog='specter.py')
    subparsers = parser.add_subparsers(title='subcommands',
                                       description='Valid specter subcommands',
                                       dest='subcommand',
                                       required=True)
    _init_web_scan_parser(subparsers)
    _init_port_scan_parser(subparsers)
    _init_xml_scan_parser(subparsers)
    _init_clean_list_parser(subparsers)
    parse_args(parser)


if __name__ == '__main__':
    main()
