from termcolor import colored


def log_error(msg):
    print(colored(msg, 'red'))


def log_info(msg):
    print(colored(msg, 'blue'))


def log_success(msg):
    print(colored(msg, 'green'))


def log_warning(msg):
    print(colored(msg, 'yellow'))
