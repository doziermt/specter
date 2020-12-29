import os


def resolve():
    """Returns the path to the `specter_workdir` directory."""
    cwd = os.getcwd()
    if cwd.endswith('specter_workdir'):
        return cwd
    return os.path.join(cwd, 'specter_workdir')
