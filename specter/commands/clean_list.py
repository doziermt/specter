from importlib import import_module
import os
import tempfile

from specter.commands import Command
from specter.config import load_settings
from specter.enums import Applications


class CleanList(Command):
    APPLICATION = Applications.NMAP.value

    @property
    def target_list_file_name(self):
        path = os.path.join(
            self.input_directory,
            self.SETTINGS['clean_list']['target_list_file_name'])
        self.validate_input_file_path(path,
                                      "[clean_list].target_list_file_name")
        return path

    @property
    def exclude_list_file_name(self):
        path = os.path.join(
            self.input_directory,
            self.SETTINGS['clean_list']['exclude_list_file_name'])
        self.validate_input_file_path(path,
                                      "[clean_list].exclude_list_file_name")
        return path

    @property
    def xml_clean_target_list_file_name(self):
        path = os.path.join(
            self.output_directory,
            self.SETTINGS['xml_scan']['clean_target_list_file_name'])
        return path

    def __init__(self):
        super().__init__()
        self.SETTINGS = load_settings()
        self.input_directory = os.path.join(os.getcwd(), 'specter_workdir', 'input')
        self.output_directory = self.build_specter_output_folder_structure(
            self.SETTINGS.general.sitename, use_existing=False)

    def execute(self):
        # Create a temporary file in order to temporarily dump out all the contents to a file
        # since we cannot capture stdout directly. This allows subprocess.run to dump stdout
        # to the terminal; afterward, we can re-analyze the stdout output by opening up the
        # tempfile, formatting its contents, and dumping the formatted output to the real
        # "clean target list" file.
        _, temporary_file = tempfile.mkstemp(prefix='specter')

        command = [
            self.APPLICATION, "-sL", "-n", "-iL", self.target_list_file_name,
            "--excludefile", self.exclude_list_file_name, "-oN", temporary_file
        ]
        self.run_command(command)

        with open(temporary_file, 'r') as readfile:
            relevant_lines = readfile.readlines()[1:-2]
            formatted_lines = [line.split(' ')[-1] for line in relevant_lines]

        with open(self.xml_clean_target_list_file_name, 'w') as outfile:
            outfile.writelines(formatted_lines)
