import ipaddress
import os
import subprocess
import xml.etree.ElementTree as ET

from specter.commands import Command
from specter.config import settings
from specter.enums import Applications


class XmlScan(Command):
    APPLICATION = Applications.MASSCAN.value

    WEB_PORTS_TO_SCAN = (
        ("tcp", "443"),
        ("tcp", "80"),
        ("tcp", "8000"),
        ("tcp", "8080"),
        ("tcp", "8443"),
    )

    MASSCAN_XML_OUTPUT_PATH = 'output/xml/masscan.xml'

    @property
    def sitename(self):
        return settings.general.sitename

    @property
    def web_clean_target_list_file_path(self):
        path = os.path.abspath(
            settings['web_scan']['clean_target_list_file_path'])
        self.validate_target_file_path(
            path, "[web_scan].clean_target_list_file_path")
        return path

    @property
    def xml_clean_target_list_file_path(self):
        """First checks whether clean_list has generated the clean target list for this operation
        and then returns the configuration value.
        """
        path = settings['xml_scan']['clean_target_list_file_path']
        if not os.path.exists(os.path.abspath(path)):
            raise FileNotFoundError(
                "Could not find [xml_scan].clean_target_list_file_path. "
                "Please run \"clean_list\" operation first before running \"xml_scan\"."
            )
        return os.path.abspath(path)

    @property
    def ip(self):
        return settings['xml_scan']['masscan_ip']

    @property
    def interface(self):
        return settings['xml_scan']['interface']

    @property
    def ports(self):
        ports = settings['xml_scan']['ports'].to_list()
        return ",".join(["%s" % port for port in ports])

    @property
    def scan_rate(self):
        return settings['xml_scan']['scan_rate']

    def __init__(self):
        super().__init__()

    def _parse_masscan_xml_for_ip_addresses(self, filename, target_protocol,
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

    def _parse_masscan_xml_for_port_ip_address_mapping(self, filename):
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

    def _parse_masscan_xml_for_ip_address_port_mapping(self, filename):
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

        return ip_address_port_map

    def _write_output_to_file(self, filename, ip_addresses):
        if isinstance(ip_addresses, set):
            ip_addresses = list(ip_addresses)

        ip_addresses.sort()

        with open(filename, 'w') as out:
            out.writelines("\n".join([str(x) for x in ip_addresses]))

    def _generate_output_files_from_masscan_xml(self):
        all_ip_addresses = set()
        for (protocol, portid) in self.WEB_PORTS_TO_SCAN:
            ip_addresses = self._parse_masscan_xml_for_ip_addresses(
                self.MASSCAN_XML_OUTPUT_PATH, protocol, portid)
            all_ip_addresses = all_ip_addresses.union(ip_addresses)
        self._write_output_to_file(self.web_clean_target_list_file_path,
                                   all_ip_addresses)

        port_ip_addresses_map = self._parse_masscan_xml_for_port_ip_address_mapping(
            self.MASSCAN_XML_OUTPUT_PATH)
        for (port, ip_addresses) in port_ip_addresses_map.items():
            self._write_output_to_file("output/ports/%s.txt" % port,
                                       ip_addresses)

        ip_addresses_port_map = self._parse_masscan_xml_for_ip_address_port_mapping(
            self.MASSCAN_XML_OUTPUT_PATH)
        for (ip_address, output) in ip_addresses_port_map.items():
            self._write_output_to_file("output/hosts/%s.txt" % ip_address,
                                       output)

    def execute(self):
        command = " ".join([
            self.APPLICATION, "--max-retries=1", "--banners", "--source-ip",
            self.ip, "--source-port 61000", "--open", "-e", self.interface,
            "-p", self.ports, "-iL", self.xml_clean_target_list_file_path,
            "--rate=%d" % self.scan_rate,
            "-oX %s" % self.MASSCAN_XML_OUTPUT_PATH
        ])
        self.run_command(command)
        self._generate_output_files_from_masscan_xml()
