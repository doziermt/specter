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
        """Runs a subprocess command using `subprocess.run`.

        The `stdout` of the process is emitted to the terminal, but `stderr` is piped back to subprocess so that
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
            'Calling %s via subprocess.run() with the following command: %s' %
            (cls.APPLICATION, command))
        print()

        proc = None

        try:
            use_shell = isinstance(command, str)
            proc = subprocess.run(command,
                                  shell=use_shell,
                                  check=True,
                                  universal_newlines=True,
                                  stderr=subprocess.PIPE)
        except subprocess.SubprocessError as e:
            raise exceptions.SubprocessExecutionError(
                "Failed to execute operation '%s'. Command '%s' returned non-zero exit status %d. Error from %s:\n\n%s"
                % (op_name, command, e.returncode, cls.APPLICATION, e.stderr))
        finally:
            if proc is not None and proc.returncode != 0:
                raise exceptions.SubprocessExecutionError(
                    "Failed to execute operation '%s'. Command '%s' returned non-zero exit status %d. Error from %s:\n\n%s"
                    % (op_name, command, proc.returncode, cls.APPLICATION,
                       proc.stderr))

        print("Successfully finished '%s' operation." % op_name)

    @abstractmethod
    def __init__(self):
        self.timestamp = '{:%Y-%m-%d_%H-%M-%S}'.format(datetime.datetime.now())
        self.validate_binary()

    @abstractmethod
    def execute(self):
        """Method for executing the CLI applications associated with this `Command`."""
        pass
