from abc import ABCMeta, abstractmethod
import datetime
import subprocess

import inflection
from specter import exceptions


class Command(object, metaclass=ABCMeta):
    """Abstract base class that all commands should inherit from."""
    APPLICATION = None

    @classmethod
    def validate_binary(cls):
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
        if not command:
            raise TypeError(
                "The command passed to %s.run_command must be provided" %
                cls.__name__)

        op_name = inflection.underscore(cls.__name__)
        print('Running %s operation...' % op_name)
        print(
            'Calling %s via subprocess.run() with the following command: %s' %
            (cls.APPLICATION, command))
        print()

        output = subprocess.run(command,
                                shell=True,
                                universal_newlines=True,
                                capture_output=True)
        if output.returncode != 0:
            application_error_msg = output.stderr or output.stdout
            raise exceptions.SubprocessExecutionError(
                "Failed to execute operation '%s'. Command '%s' returned non-zero exit status %d. Error from %s:\n\n%s"
                % (op_name, command, output.returncode, cls.APPLICATION,
                   application_error_msg))

        print("Captured %s output: %s" %
              (cls.APPLICATION, output.stdout or output.stderr))
        print("Successfully finished '%s' operation." % op_name)

        return output

    @abstractmethod
    def __init__(self):
        self.timestamp = '{:%Y-%m-%d_%H-%M-%S}'.format(datetime.datetime.now())
        self.validate_binary()

    @abstractmethod
    def execute(self):
        """Method for executing the CLI applications associated with this `Command`."""
        pass
