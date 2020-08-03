import os

from specter.commands import Command
from specter.config import settings
from specter.enums import Applications


class CleanList(Command):
    APPLICATION = Applications.NMAP.value

    @property
    def xml_clean_target_list_file_path(self):
        path = os.path.abspath(settings['xml_scan']['clean_target_list_file_path'])
        self._validate_target_file_path(path, "[xml_scan].clean_target_list_file_path")
        return path

    @property
    def target_list_file_path(self):
        path = os.path.abspath(settings['clean_list']['target_list_file_path'])
        self._validate_target_file_path(path, "[clean_list].target_list_file_path")
        return path

    @property
    def exclude_list_file_path(self):
        path = os.path.abspath(settings['clean_list']['exclude_list_file_path'])
        self._validate_target_file_path(path, "[clean_list].exclude_list_file_path")
        return path

    def __init__(self):
        super().__init__()

    def execute(self):
        command = " ".join([
            self.APPLICATION, "-sL", "-n", "-iL",
            self.target_list_file_path,
            "--excludefile",
            self.exclude_list_file_path,
            "-oN",
            self.xml_clean_target_list_file_path
        ])
        output = self.run_command(command)

        relevant_output = output.stdout.split("\n")[1:-2]
        formatted_output = [
            line.split(' ')[-1] + '\n' for line in relevant_output
        ]

        with open(self.xml_clean_target_list_file_path, 'w') as outfile:
            outfile.writelines(formatted_output)

    def _validate_target_file_path(self, path, settings_name):
        if not os.path.exists(path):
            try:
                os.utime(path, None)
            except OSError:
                with open(path, 'a'):
                    pass
        else:
            if not os.path.isfile(path):
                raise FileNotFoundError(
                    'The "%s" must reference a file, not a directory' % settings_name)
