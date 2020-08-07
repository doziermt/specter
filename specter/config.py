import os
import socket
import sys
import traceback

from dynaconf import Dynaconf, Validator
from dynaconf.validator import ValidationError


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False

    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        return False
    return True


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
    ip_address = settings.xml_scan.masscan_ip
    if not is_valid_ipv4_address(ip_address) and not is_valid_ipv6_address(
            ip_address):
        raise ValidationError(
            "Failed validation for `[xml_scan].masscan_ip`. Reason: %s is neither a valid ipv4 nor ipv6 address"
            % ip_address)


def validate_settings(config_file_name='settings.toml'):
    settings = Dynaconf(
        environments=False,
        load_dotenv=False,
        settings_files=[os.path.join(os.getcwd(), config_file_name)],
        validators=[
            Validator('general', must_exist=True),
            Validator('general.sitename', must_exist=True, is_type_of=str),
            Validator('clean_list', must_exist=True),
            Validator('clean_list.exclude_list_file_path',
                      must_exist=True,
                      is_type_of=str),
            Validator('clean_list.target_list_file_path',
                      must_exist=True,
                      is_type_of=str),
            Validator('web_scan', must_exist=True),
            Validator('web_scan.clean_target_list_file_path',
                      must_exist=True,
                      is_type_of=str),
            Validator('web_scan.jitter',
                      must_exist=True,
                      is_type_of=int,
                      gte=0),
            Validator('web_scan.ports', must_exist=True, is_type_of=str),
            Validator('xml_scan', must_exist=True),
            Validator('xml_scan.clean_target_list_file_path',
                      must_exist=True,
                      is_type_of=str),
            Validator('xml_scan.masscan_ip', must_exist=True, is_type_of=str),
            Validator('xml_scan.interface', must_exist=True, is_type_of=str),
            Validator('xml_scan.ports', must_exist=True, is_type_of=str),
            Validator('xml_scan.scan_rate',
                      must_exist=True,
                      is_type_of=int,
                      gte=1),
        ])

    settings.validators.validate()
    validate_port_settings(settings)
    validate_ip_address_settings(settings)

    return settings


if __name__ == '__main__':
    # Validate the config file provided from the CLI if this script is called from there.
    try:
        settings_path = sys.argv[1] if len(sys.argv) > 1 else 'settings.toml'
        validate_settings(settings_path)
    except ValidationError as e:
        tb = sys.exc_info()[2]
        traceback.print_exception(e.__class__, e, tb, limit=2, file=sys.stdout)
        error_message = 'Dynaconf validation failed for config file: %s' % settings_path
        sys.exit(error_message)
else:
    # Otherwise imported from specter.py, load & validate the settings.
    settings = validate_settings()
