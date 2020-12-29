import os
import sys
import traceback

import ipaddress

from dynaconf import Dynaconf, Validator
from dynaconf.validator import ValidationError

SETTINGS = None

__all__ = ('load_settings', 'validate_settings')


def load_settings():
    global SETTINGS
    validate_settings()
    return SETTINGS


def validate_settings(settings_file_path=None):
    global SETTINGS

    settings_file_path = settings_file_path or os.path.join(
        os.getcwd(), 'specter_workdir', 'settings.toml')

    if not os.path.exists(settings_file_path):
        raise FileNotFoundError(
            'Could not find the settings file at path: %s' %
            settings_file_path)
    if not os.path.isfile(settings_file_path):
        raise TypeError(
            'The settings file path must reference a valid TOML file: %s' %
            settings_file_path)

    SETTINGS = Dynaconf(environments=False,
                        load_dotenv=False,
                        settings_files=[settings_file_path],
                        validators=[
                            Validator('general', must_exist=True),
                            Validator('general.sitename',
                                      must_exist=True,
                                      is_type_of=str),
                            Validator('clean_list', must_exist=True),
                            Validator('clean_list.nmap_target_list_file_name',
                                      must_exist=True,
                                      is_type_of=str),
                            Validator('clean_list.nmap_target_list_file_name',
                                      must_exist=True,
                                      is_type_of=str),
                            Validator('web_scan', must_exist=True),
                            Validator('web_scan.clean_target_list_file_name',
                                      must_exist=True,
                                      is_type_of=str),
                            Validator('web_scan.jitter',
                                      must_exist=True,
                                      is_type_of=int,
                                      gte=0),
                            Validator('web_scan.ports',
                                      must_exist=True,
                                      is_type_of=str),
                            Validator('xml_scan', must_exist=True),
                            Validator('xml_scan.clean_target_list_file_name',
                                      must_exist=True,
                                      is_type_of=str),
                            Validator('xml_scan.masscan_ip',
                                      must_exist=True,
                                      is_type_of=str),
                            Validator('xml_scan.interface',
                                      must_exist=True,
                                      is_type_of=str),
                            Validator('xml_scan.ports',
                                      must_exist=True,
                                      is_type_of=str),
                            Validator('xml_scan.scan_rate',
                                      must_exist=True,
                                      is_type_of=int,
                                      gte=1),
                        ])

    SETTINGS.validators.validate()
    validate_port_settings(SETTINGS)
    validate_ip_address_settings(SETTINGS)


def load_clean_list_file_input(settings_name, filepath):
    abspath = os.path.abspath(filepath)
    if not os.path.exists(abspath):
        specter_workdir_path = os.path.join(os.getcwd(), 'specter_workdir')
        abspath = os.path.join(specter_workdir_path, filepath)
        if not os.path.exists(abspath):
            reason = "Could not resolve the file path: %s" % filepath
            raise ValidationError(
                "Failed validation for `[clean_list].%s`. Reason: %s" %
                (settings_name, reason))
    with open(abspath) as f:
        lines = [line.strip() for line in f.readlines()]
    return lines


def load_clean_list_file_path(settings_name, filepath):
    abspath = os.path.abspath(filepath)
    if not os.path.exists(abspath):
        specter_workdir_path = os.path.join(os.getcwd(), 'specter_workdir')
        abspath = os.path.join(specter_workdir_path, filepath)
        if not os.path.exists(abspath):
            reason = "Could not resolve the file path: %s" % filepath
            raise ValidationError(
                "Failed validation for `[clean_list].%s`. Reason: %s" %
                (settings_name, reason))
    return abspath


def validate_ip_addresses(ip_addresses):
    def validate_ip_address(ip_address):
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return False, "%s is neither a valid IPv4 nor IPv6 address" % ip_address
        return True, None

    def validate_ip_address_range(ip_address_range):
        def validate_range_value(value):
            return value >= 0 and value < 255

        try:
            parts = ip_address_range.split('.')
            if len(parts) != 4:
                return False, "%s is not a valid IP address range: malformatted IP range" % ip_address_range
            for part in parts:
                if '-' in part:
                    start, end = part.split('-')
                    start_val = int(start)
                    end_val = int(end)

                    if not validate_range_value(start_val):
                        return False, "%s is not a valid IP address range: start range value illegal" % ip_address_range
                    if not validate_range_value(end_val):
                        return False, "%s is not a valid IP address range: end range value illegal" % ip_address_range
                    if start_val > end_val:
                        return False, "%s is not a valid IP address range: start range value bigger than end range value" % ip_address_range
                else:
                    if not validate_range_value(int(part)):
                        return False, "%s is not a valid IP address range: IP value illegal" % ip_address_range
        except Exception:
            return False, "%s is not a valid IP address range" % ip_address_range
        return True, None

    def validate_ip_network(ip_network):
        try:
            ipaddress.ip_network(ip_network)
        except ValueError:
            return False, "%s is not a valid IP network address" % ip_network
        return True, None

    def validate_ip_address_option(ip_address_option):
        if not ip_address_option:
            return False, "Null/empty IP address detected"

        if '/' in ip_address_option:
            return validate_ip_network(ip_address_option)
        elif '-' in ip_address_option:
            return validate_ip_address_range(ip_address_option)
        else:
            return validate_ip_address(ip_address_option)

    if isinstance(ip_addresses, list):
        if ip_addresses is None:
            return False, ["A valid list of IP addresses must be provided"]
        ip_address_list = ip_addresses
    else:
        if not ip_addresses:
            return False, ["A valid list of IP addresses must be provided"]
        ip_address_list = ip_addresses.split(',')

    validation_results = [
        validate_ip_address_option(ip_address)
        for ip_address in ip_address_list
    ]
    validation_failures = [
        result[1] for result in validation_results if result[0] is False
    ]
    return len(validation_failures) == 0, validation_failures


def validate_ports(ports):
    def validate_port(port):
        try:
            int(port)
        except ValueError:
            return False, "%s is not a valid port number" % port
        return True, None

    def validate_port_option(port_option):
        if not port_option:
            return False, "Null/empty port detected"

        # Check for valid port range and validate each value in the range.
        if '-' in port_option:
            port_range = port_option.split('-')

            if not len(port_range) == 2:
                return False, "%s is an invalid port range" % port_option

            for port in port_range:
                result = validate_port(port)
                if not result[0]:
                    return result

            return True, None
        # Otherwise, assume the value is a port number and validate it.
        else:
            return validate_port(port_option)

    if not ports:
        return False, ["A valid list of ports or port ranges is required"]

    port_list = ports.split(',')
    validation_results = [validate_port_option(port) for port in port_list]
    validation_failures = [
        result[1] for result in validation_results if result[0] is False
    ]
    return len(validation_failures) == 0, validation_failures


def validate_port_settings(settings):
    """Validate that each of the port settings (``[xml_scan].ports`` and ``[web_scan].ports``) are valid."""
    webscan_ports_validation_results = validate_ports(settings.web_scan.ports)
    if not webscan_ports_validation_results[0]:
        raise ValidationError(
            "Failed validation for `[web_scan].ports`. Reason: %s" %
            ",".join(webscan_ports_validation_results[1]))
    xml_scan_ports_validation_results = validate_ports(settings.xml_scan.ports)
    if not xml_scan_ports_validation_results[0]:
        raise ValidationError(
            "Failed validation for `[xml_scan].ports`. Reason: %s" %
            ",".join(xml_scan_ports_validation_results[1]))


def validate_ip_address_settings(settings):
    """Validates that each of the IP address settings are valid."""
    # Validate nmap_target_list filepath.
    nmap_target_list = load_clean_list_file_input(
        "nmap_target_list_file_name",
        settings.clean_list.nmap_target_list_file_name)

    # Validate nmap_target_list IP addresses.
    nmap_target_list_validation_results = validate_ip_addresses(
        nmap_target_list)
    if not nmap_target_list_validation_results[0]:
        raise ValidationError(
            "Failed validation for `[clean_list].nmap_target_list`. Reason: %s"
            ",".join(nmap_target_list_validation_results[1]))

    # Validate nmap_exclude_list filepath.
    nmap_exclude_list = load_clean_list_file_input(
        "nmap_exclude_list_file_name",
        settings.clean_list.nmap_exclude_list_file_name)

    # Validate nmap_exclude_list IP addresses.
    nmap_exclude_list_validation_results = validate_ip_addresses(
        nmap_exclude_list)
    if not nmap_exclude_list_validation_results[0]:
        raise ValidationError(
            "Failed validation for `[clean_list].nmap_exclude_list`. Reason: %s"
            ",".join(nmap_exclude_list_validation_results[1]))

    # Validate masscan_ip.
    masscan_ip_address = settings.xml_scan.masscan_ip
    masscan_ip_validation_results = validate_ip_addresses(masscan_ip_address)
    if not masscan_ip_validation_results[0]:
        raise ValidationError(
            "Failed validation for `[xml_scan].masscan_ip`. Reason: %s" %
            ",".join(masscan_ip_validation_results[1]))


def main():
    # Validate the config file provided from the CLI if this script is called from there.
    try:
        settings_path = sys.argv[1] if len(sys.argv) > 1 else 'settings.toml'
        validate_settings(settings_path)
    except ValidationError as e:
        tb = sys.exc_info()[2]
        traceback.print_exception(e.__class__, e, tb, limit=2, file=sys.stdout)
        error_message = 'Dynaconf validation failed for config file: %s' % settings_path
        sys.exit(error_message)


if __name__ == '__main__':
    main()
