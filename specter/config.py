import os
import sys
import traceback

from dynaconf import Dynaconf, Validator
from dynaconf.validator import ValidationError


def _build_output_directory_hierarchy():
    if not os.path.exists('output'):
        os.makedirs(dirname, exist_ok=True)


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
            Validator('web_scan.ports', must_exist=True, is_type_of=list),
            Validator('xml_scan', must_exist=True),
            Validator('xml_scan.clean_target_list_file_path',
                      must_exist=True,
                      is_type_of=str),
            Validator('xml_scan.masscan_ip', must_exist=True, is_type_of=str),
            Validator('xml_scan.interface', must_exist=True, is_type_of=str),
            Validator('xml_scan.ports', must_exist=True, is_type_of=list),
            Validator('xml_scan.scan_rate',
                      must_exist=True,
                      is_type_of=int,
                      gte=1),
        ])

    settings.validators.validate()
    _build_output_directory_hierarchy()

    return settings


if __name__ == '__main__':
    # Validate the sample config file if calling this via tox.
    try:
        sample_conf_rel_path = 'samples/settings.sample.toml'
        validate_settings(sample_conf_rel_path)
    except ValidationError as e:
        tb = sys.exc_info()[2]
        traceback.print_exception(e.__class__, e, tb, limit=2, file=sys.stdout)
        error_message = 'Dynaconf validation failed for config file: %s' % sample_conf_rel_path
        sys.exit(error_message)
else:
    # Otherwise imported from specter.py, load & validate the settings.
    settings = validate_settings()
