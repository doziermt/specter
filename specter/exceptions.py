class SpecterBaseException(Exception):
    pass


class IllegalExecutionException(SpecterBaseException):
    pass


class AppDependencyNotFoundException(SpecterBaseException):
    pass


class SubprocessExecutionException(SpecterBaseException):
    pass


class OutputParseException(SpecterBaseException):
    pass
