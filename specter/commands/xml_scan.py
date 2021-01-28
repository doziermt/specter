import ipaddress
import os
import subprocess
from xml.etree import ElementTree

from specter.commands import Command
from specter.config import load_settings
from specter.enums import Applications
from specter import exceptions
from specter.utils import log_warning


class XmlScan(Command):
    APPLICATION = Applications.MASSCAN.value

    WEB_PORTS_TO_SCAN = (
        ("tcp", "443"),
        ("tcp", "80"),
        ("tcp", "8000"),
        ("tcp", "8080"),
        ("tcp", "8443"),
    )

    @property
    def sitename(self):
        return self.SETTINGS.general.sitename

    @property
    def masscan_xml_path(self):
        return os.path.join(self.output_directory, "xml/masscan.xml")

    @property
    def xml_clean_target_list_file_name(self):
        """First checks whether clean_list has generated the clean target list for this operation
        and then returns the configuration value.
        """
        path = os.path.join(
            self.output_directory,
            self.SETTINGS['xml_scan']['clean_target_list_file_name'])
        self.validate_input_file_path(
            path, "[xml_scan].clean_target_list_file_name")
        return path

    @property
    def web_clean_target_list_file_name(self):
        path = os.path.join(
            self.output_directory,
            self.SETTINGS['web_scan']['clean_target_list_file_name'])
        self.validate_output_file_path(
            path, "[web_scan].clean_target_list_file_name")
        return path

    @property
    def ip(self):
        return self.SETTINGS['xml_scan']['masscan_ip']

    @property
    def interface(self):
        return self.SETTINGS['xml_scan']['interface']

    @property
    def ports(self):
        return self.SETTINGS['xml_scan']['ports']

    @property
    def scan_rate(self):
        return self.SETTINGS['xml_scan']['scan_rate']

    def __init__(self):
        super().__init__()
        self.SETTINGS = load_settings()
        self.output_directory = self.build_specter_output_folder_structure(
            self.SETTINGS.general.sitename, use_existing=True)

    def _parse_masscan_xml_for_ip_addresses(self, root, target_protocol,
                                            target_portid):
        ip_addresses = set()
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

    def _parse_masscan_xml_for_port_ip_address_mapping(self, root):
        port_ip_address_map = dict()
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

    def _parse_masscan_xml_for_ip_address_port_mapping(self, root):
        ip_address_port_map = dict()
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

        return ip_address_port_map

    def _write_output_to_file(self, filename, ip_addresses):
        if isinstance(ip_addresses, set):
            ip_addresses = list(ip_addresses)

        ip_addresses.sort()

        with open(filename, 'w') as out:
            out.writelines("\n".join([str(x) for x in ip_addresses]))

    def _generate_output_files_from_masscan_xml(self):
        try:
            tree = ElementTree.parse(self.masscan_xml_path)
            root = tree.getroot()
        except ElementTree.ParseError as e:
            return log_warning(
                "XML file [%s] could not be parsed because it is most likely empty. Skipping."
                % self.masscan_xml_path)

        all_ip_addresses = set()

        for (protocol, portid) in self.WEB_PORTS_TO_SCAN:
            try:
                ip_addresses = self._parse_masscan_xml_for_ip_addresses(
                    root, protocol, portid)
            except ElementTree.ParseError as e:
                raise exceptions.OutputParseException(
                    "Failed to generate clean target list for web_scan operation. Reason: %s"
                    % e)

            all_ip_addresses = all_ip_addresses.union(ip_addresses)
        self._write_output_to_file(self.web_clean_target_list_file_name,
                                   all_ip_addresses)

        try:
            port_ip_addresses_map = self._parse_masscan_xml_for_port_ip_address_mapping(
                root)
        except ElementTree.ParseError as e:
            raise exceptions.OutputParseException(
                "Failed to generate port output files for xml_scan. Reason: %s"
                % e)

        for (port, ip_addresses) in port_ip_addresses_map.items():
            self._write_output_to_file(
                os.path.join(self.output_directory, "ports", "%s.txt" % port),
                ip_addresses)

        try:
            ip_addresses_port_map = self._parse_masscan_xml_for_ip_address_port_mapping(
                root)
        except ElementTree.ParseError as e:
            raise exceptions.OutputParseException(
                "Failed to generate host output files for xml_scan. Reason: %s"
                % e)

        for (ip_address, output) in ip_addresses_port_map.items():
            self._write_output_to_file(
                os.path.join(self.output_directory, "hosts",
                             "%s.txt" % ip_address), output)

    def execute(self, *args, include_banners=False, **kwargs):
        #if include_banners:
        #command = [
        #    "nmap -sT --open -p10-100",
        #    "-iL", self.xml_clean_target_list_file_name,
        #    "-oA %s_banners" % self.masscan_xml_path
        #]
        #self.run_command(command, 'with banners included')
        #else:
        command = [
            self.APPLICATION, "--max-retries=1", "--open", "-e",
            self.interface, "-p", self.ports, "-iL",
            self.xml_clean_target_list_file_name,
            "--rate=%d" % self.scan_rate,
            "-oX %s" % self.masscan_xml_path
        ]
        self.run_command(command, 'with NO banners included')
        self._generate_output_files_from_masscan_xml()
