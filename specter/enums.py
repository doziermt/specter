from enum import Enum


class Applications(Enum):
    MASSCAN = 'masscan'
    NMAP = 'nmap'
    EYEWITNESS = 'eyewitness'


class Commands(Enum):
    INIT = 'init'
    TREE = 'tree'
    CLEAN_LIST = 'clean_list'
    XML_SCAN = 'xml_scan'
    WEB_SCAN = 'web_scan'
