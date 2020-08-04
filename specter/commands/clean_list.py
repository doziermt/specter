import os
import tempfile

from specter.commands import Command
from specter.config import settings
from specter.enums import Applications


class CleanList(Command):
    APPLICATION = Applications.NMAP.value

    @property
    def xml_clean_target_list_file_path(self):
        path = os.path.abspath(
            settings['xml_scan']['clean_target_list_file_path'])
        self._validate_target_file_path(
            path, "[xml_scan].clean_target_list_file_path")
        return path

    @property
    def target_list_file_path(self):
        path = os.path.abspath(settings['clean_list']['target_list_file_path'])
        self._validate_target_file_path(path,
                                        "[clean_list].target_list_file_path")
        return path

    @property
    def exclude_list_file_path(self):
        path = os.path.abspath(
            settings['clean_list']['exclude_list_file_path'])
        self._validate_target_file_path(path,
                                        "[clean_list].exclude_list_file_path")
        return path

    def __init__(self):
        super().__init__()

    def execute(self):
        # Create a temporary file in order to temporarily dump out all the contents to a file
        # since we cannot capture stdout directly. This allows subprocess.run to dump stdout
        # to the terminal; afterward, we can re-analyze the stdout output by opening up the
        # tempfile, formatting its contents, and dumping the formatted output to the real
        # "clean target list" file.
        _, temporary_file = tempfile.mkstemp(prefix='specter')

        command = [
            self.APPLICATION, "-sL", "-n", "-iL", self.target_list_file_path,
            "--excludefile", self.exclude_list_file_path, "-oN", temporary_file
        ]
        self.run_command(command)

        with open(temporary_file, 'r') as readfile:
            relevant_lines = readfile.readlines()[1:-2]
            formatted_lines = [line.split(' ')[-1] for line in relevant_lines]

        with open(self.xml_clean_target_list_file_path, 'w') as outfile:
            outfile.writelines(formatted_lines)

    def _validate_target_file_path(self, path, settings_alias):
        # If the file doesn't exist, quickly create it.
        # Also, if the file does already exist, make sure that it is not a directory.
        if not os.path.exists(path):
            try:
                os.utime(path, None)
            except OSError:
                with open(path, 'a'):
                    pass
        else:
            if not os.path.isfile(path):
                raise FileNotFoundError(
                    'Failed to locate file: The "%s" option in settings.toml must reference a file, not a directory'
                    % settings_alias)
            if not os.access(path, os.R_OK):
                raise IOError(
                    'Failed to read file: The "%s" option in settings.toml must be a readable file'
                    % settings_alias)
