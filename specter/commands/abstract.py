from abc import ABCMeta, abstractmethod
from datetime import datetime
import os
import subprocess

import inflection

from specter import exceptions
from specter.utils import log_info, log_success


class Command(object, metaclass=ABCMeta):
    """Abstract base class that all commands should inherit from."""

    # Each sub-class that uses a 3rd-party app must provide a value for `APPLICATION`.
    # Examples include ``Applications.NMAP.value`` or ``Applications.MASSCAN.value``.
    APPLICATION = None

    @classmethod
    def validate_application_exists(cls):
        """Validates that the application binary specified by `self.APPLICATION` exists in the system."""
        # Only perform the check for commands that have a 3rd-party application dependency.
        if cls.APPLICATION is None:
            return

        command = "command -v %s" % cls.APPLICATION
        output = subprocess.run(command,
                                shell=True,
                                universal_newlines=True,
                                capture_output=True)
        if output.returncode != 0:
            raise exceptions.AppDependencyNotFoundException(
                "Could not find application '%s' required to run this command. Please install it then try again."
                % cls.APPLICATION)

    @classmethod
    def run_command(cls, command):
        """Runs a subprocess command using ``subprocess.run``.

        The ``stdout`` and ``stderr`` are both emitted to the console since neither are captured.

        :param list command: A command to run in a subprocess.
        :returns: None
        """
        if not command:
            raise RuntimeError(
                "The command passed to %s.run_command must be provided" %
                cls.__name__)

        op_name = inflection.underscore(cls.__name__)
        log_info('Running %s operation...' % op_name)
        log_info(
            'Calling %s via subprocess.run() with the following command:\n\n%s\n'
            % (cls.APPLICATION, command))

        def handle_error(process):
            raise exceptions.SubprocessExecutionException(
                "Failed to execute operation '%s'. Reason: subprocess.run() returned non-zero exit status %d for last-executed command."
                % (op_name, process.returncode))

        try:
            # In case a string is passed for `command` instead, attempt to handle it.
            use_shell = isinstance(command, str)
            proc = subprocess.run(command,
                                  shell=use_shell,
                                  check=True,
                                  universal_newlines=True)
        except subprocess.SubprocessError as e:
            handle_error(e)
        else:
            if proc.returncode != 0:
                handle_error(proc)

        log_success("Successfully finished '%s' operation." % op_name)

    @classmethod
    def validate_input_file_path(cls, file_path, settings_alias):
        """Validates that ``file_path`` isn't a directory and the user has permissons to read it."""
        cls._validate_path_exists(file_path, settings_alias)
        cls._validate_path_access(file_path,
                                  settings_alias,
                                  access_level=os.R_OK)

    @classmethod
    def validate_output_file_path(cls, file_path, settings_alias=None):
        """Validates that user has permissions to read ``file_path``."""
        directory_path = os.path.dirname(file_path)
        cls._validate_path_access(directory_path,
                                  settings_alias,
                                  access_level=os.W_OK)

    @classmethod
    def build_specter_output_folder_structure(
        cls,
        sitename,
        use_existing,
    ):
        root_output_directory = os.path.join(os.getcwd(), 'specter_workdir',
                                             'output')

        def _generate_new_subdirectory_name(sitename):
            new_timestamp = str(datetime.now()).replace(' ', '_')
            return '_'.join([sitename, new_timestamp])

        def _get_existing_subdirectory_name():
            def sort_by_timestamp(directory):
                timestamp = ' '.join(directory.split('_')[1:])
                return datetime.fromisoformat(timestamp)

            candidates = [
                directory for directory in os.listdir(root_output_directory)
                if directory.startswith(sitename + '_')
            ]
            return sorted(candidates, key=sort_by_timestamp)[0]

        output_directory = os.path.join(
            root_output_directory,
            _get_existing_subdirectory_name()
            if use_existing else _generate_new_subdirectory_name(sitename))

        subdirectories = {
            os.path.abspath('%s/hosts' % output_directory),
            os.path.abspath('%s/ports' % output_directory),
            os.path.abspath('%s/web_reports/eyewitness' % output_directory),
            os.path.abspath('%s/xml' % output_directory),
        }
        for directory in subdirectories:
            if not os.path.isdir(directory):
                log_info('Creating output sub-directories: %s' % directory)
            os.makedirs(directory, exist_ok=True)

        return output_directory

    @classmethod
    def _validate_path_exists(cls, path, settings_alias):
        if not os.path.exists(path) or not os.path.isfile(path):
            raise FileNotFoundError(
                'File path "%s" is not valid. Reason: The "%s" option in settings.toml must exist and reference a file.'
                % (path, settings_alias))

    @classmethod
    def _validate_path_access(cls, path, settings_alias, access_level):
        if not os.access(path, access_level):
            if access_level is os.R_OK:
                raise IOError(
                    'File path "%s" could not be accessed. Reason: The "%s" option in settings.toml must be a readable file.'
                    % (path, settings_alias))
            else:
                raise IOError(
                    'Path "%s" could not be written to. Please validate the Specter Work Directory folder permissions.'
                    % path)

    @abstractmethod
    def __init__(self):
        """Constructor for sub-classes of ``Command``.
        All sub-classes must implement this and call ``super().__init__()``.

        Example::

            class CustomSampleCommand(Command):
                def __init__(self):
                    super().__init__()
        """
        self.validate_application_exists()

    @abstractmethod
    def execute(self):
        """Method for executing the CLI applications associated with this ``Command``.
        All sub-classes must implement this.
        """
        pass
