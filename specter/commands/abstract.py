from abc import ABCMeta, abstractmethod
import datetime
import os
import subprocess

import inflection
from specter import exceptions


class Command(object, metaclass=ABCMeta):
    """Abstract base class that all commands should inherit from."""
    """All sub-classes must specify this. Examples include ``Applications.NMAP.value`` or ``Applications.MASSCAN.value``."""
    APPLICATION = None

    @classmethod
    def validate_binary(cls):
        """Validates that the application binary specified by `self.APPLICATION` exists in the system."""
        if cls.APPLICATION is None:
            raise TypeError("APPLICATION must be defined for class: %s" %
                            cls.__name__)

        command = "command -v %s" % cls.APPLICATION
        output = subprocess.run(command,
                                shell=True,
                                universal_newlines=True,
                                capture_output=True)
        if output.returncode != 0:
            raise exceptions.AppDependencyNotFoundError(
                "Could not find application '%s' required to run this command. Please install it then try again."
                % cls.APPLICATION)

    @classmethod
    def run_command(cls, command):
        """Runs a subprocess command using ``subprocess.run``.

        The ``stdout`` of the process is emitted to the terminal, but ``stderr`` is piped back to subprocess so that
        error handling can be performed.

        :param list command: A command to run in a subprocess.
        :returns: None
        """
        if not command:
            raise TypeError(
                "The command passed to %s.run_command must be provided" %
                cls.__name__)

        op_name = inflection.underscore(cls.__name__)
        print('Running %s operation...' % op_name)
        print(
            'Calling %s via subprocess.run() with the following command:\n\n%s'
            % (cls.APPLICATION, command))
        print()

        def handle_error(process):
            raise exceptions.SubprocessExecutionError(
                "Failed to execute operation '%s'. Reason: subprocess.run() returned non-zero exit status %d for command:\n\n%s."
                % (op_name, process.returncode, command))

        try:
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

        print("Successfully finished '%s' operation." % op_name)

    @classmethod
    def validate_target_file_path(cls, path, settings_alias):
        """Creates the file at ``path`` if it doesn't exist or else validates that it isn't a directory
        and the user has permissons to read it.
        """

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

    @abstractmethod
    def __init__(self):
        """Constructor for sub-classes of ``Command``.
        All sub-classes must implement this and call ``super().__init__()``.

        Example::

            class CustomSampleCommand(Command):
                def __init__(self):
                    super().__init__()
        """
        self.timestamp = '{:%Y-%m-%d_%H-%M-%S}'.format(datetime.datetime.now())
        self.validate_binary()

    @abstractmethod
    def execute(self):
        """Method for executing the CLI applications associated with this ``Command``.
        All sub-classes must implement this.
        """
        pass
