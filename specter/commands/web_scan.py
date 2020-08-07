import os

from specter.commands import Command
from specter.config import load_settings
from specter.enums import Applications


class WebScan(Command):
    APPLICATION = Applications.EYEWITNESS.value

    def __init__(self):
        super().__init__()
        self.SETTINGS = load_settings()
        self.output_directory = self.build_specter_output_folder_structure(
            self.SETTINGS.general.sitename, use_existing=True)

    @property
    def clean_target_list_file_name(self):
        """First checks whether web_scan has generated the clean target list for this operation
        and then returns the configuration value.
        """
        path = os.path.join(
            self.output_directory,
            self.SETTINGS['web_scan']['clean_target_list_file_name'])
        return path

    @property
    def ports(self):
        return self.SETTINGS['web_scan']['ports']

    @property
    def jitter(self):
        return self.SETTINGS['web_scan']['jitter'] or 0

    def execute(self):
        """Executes the web_scan command, currently only supports eyewitness."""
        command = " ".join([
            self.APPLICATION, '--web', '--add-http-ports', self.ports,
            '--add-https-ports', self.ports, '--no-prompt', '--threads 4',
            '--jitter',
            '%s' % self.jitter, '-f', self.clean_target_list_file_name,
            '-d output/web_reports/eyewitness'
        ])
        self.run_command(command)
