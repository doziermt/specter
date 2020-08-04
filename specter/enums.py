from enum import Enum
import os


class Applications(Enum):
    MASSCAN = 'masscan'
    NMAP = 'nmap'
    EYEWITNESS = 'eyewitness'
    AQUATONE = 'aquatone'


class Commands(Enum):
    PORT_SCAN = 'port_scan'
    CLEAN_LIST = 'clean_list'
    XML_SCAN = 'xml_scan'
    WEB_SCAN = 'web_scan'