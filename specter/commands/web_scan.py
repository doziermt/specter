import os

from specter.commands import Command
from specter.config import settings
from specter.enums import Applications


class WebScan(Command):
    APPLICATION = Applications.EYEWITNESS.value

    def __init__(self):
        super().__init__()

    @property
    def clean_target_list_file_path(self):
        """First checks whether web_scan has generated the clean target list for this operation
        and then returns the configuration value.
        """
        path = settings['web_scan']['clean_target_list_file_path']
        if not os.path.exists(os.path.abspath(path)):
            raise FileNotFoundError(
                "Could not find [web_scan].clean_target_list_file_path. "
                "Please run xml_scan first before running web_scan.")
        return os.path.abspath(path)

    @property
    def ports(self):
        ports = settings['web_scan']['ports'].to_list()
        return ",".join(["%s" % port for port in ports])

    @property
    def jitter(self):
        return settings['web_scan']['jitter'] or 0

    def execute(self):  
        """Executes the web_scan command, currently only supports eyewitness."""
        command = [
            self.APPLICATION,
            '--web',
            '--add-http-ports',
            self.ports,
            '--add-https-ports',
            self.ports,
            '--no-prompt',
            '--threads 4',
            '--jitter',
            self.jitter,
            '-f',
            self.clean_target_list_file_path,
            '-d output/web_reports/eyewitness'
        ].join(' ')

        import pdb; pdb.set_trace()

        self.run_command(command)

        # print()
        # print(web_command)  #Prints out the web_scan command that is running
        # print()
        # print(
        #     "Web Scan Complete, output located in specter/output/web_reports/eyewitness/ "
        # )
        # print()
