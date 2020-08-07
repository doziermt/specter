import os
import shutil

from specter.commands import Command
from specter.enums import Applications


class Init(Command):
    APPLICATION = None

    def __init__(self, root_output_directory='.specter'):
        super().__init__()
        self._root_output_directory = os.path.join(os.getcwd(),
                                                   root_output_directory)

    def execute(self):
        self.build_specter_folder_structure()
        self.copy_samples_to_target_folders()

    def build_specter_folder_structure(self):
        print('Creating specter input & output directories under: "%s"' %
              self._root_output_directory)
        os.makedirs(self._root_output_directory, exist_ok=True)
        os.makedirs(os.path.join(self._root_output_directory, 'input'),
                    exist_ok=True)
        os.makedirs(os.path.join(self._root_output_directory, 'output'),
                    exist_ok=True)

    def copy_samples_to_target_folders(self):
        current_directory = os.path.dirname(os.path.realpath(__file__))
        source_root_path = os.path.join(current_directory, os.pardir,
                                        'samples')

        for file_to_copy in os.listdir(source_root_path):
            source_file_path = os.path.join(source_root_path, file_to_copy)
            if os.path.isfile(source_file_path):
                # Rename settings.sample.toml to settings.toml in the output directory.
                if file_to_copy.endswith('.toml'):
                    target_file_path = os.path.join(os.getcwd(), '.specter',
                                                    'settings.toml')
                else:
                    target_file_path = os.path.join(os.getcwd(), '.specter',
                                                    'input', file_to_copy)
                print('Copying input file "%s" to: "%s"' %
                      (file_to_copy, target_file_path))
                shutil.copyfile(source_file_path, target_file_path)
