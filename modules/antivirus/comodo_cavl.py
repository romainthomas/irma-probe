import logging, argparse, re, os

from modules.antivirus.base import Antivirus

log = logging.getLogger(__name__)

class ComodoCAVL(Antivirus):

    ##########################################################################
    # constructor and destructor stuff
    ##########################################################################

    def __init__(self, *args, **kwargs):
        # class super class constructor
        super(ComodoCAVL, self).__init__(*args, **kwargs)
        # set default antivirus information
        self._name = "Comodo Antivirus for Linux"
        # scan tool variables
        self._scan_args = (
            "-v ", # verbose mode, display more detailed output
            "-s ", # scan a file or directory
        )
        self._scan_patterns = [
            re.compile(r'(?P<file>.*) ---\> Found .*, Malware Name is (?P<name>.*)', re.IGNORECASE)
        ]

    ##########################################################################
    # antivirus methods (need to be overriden)
    ##########################################################################

    def get_version(self):
        """return the version of the antivirus"""
        result = None
        if self.scan_path:
            dirname = os.path.dirname(self.scan_path)
            version_file = self.locate('cavver.dat', dirname)
            if version_file:
                with open(version_file[0], 'rb') as file:
                    result = file.read().strip()
        return result

    def get_database(self):
        """return list of files in the database"""
        result = None
        if self.scan_path:
            dirname = os.path.dirname(self.scan_path)
            database_path = self.locate('scanners/*.cav', dirname)
            result = database_path
        return result

    def get_scan_path(self):
        """return the full path of the scan tool"""
        paths = self.locate("cmdscan", "/opt/COMODO")
        return paths[0] if paths else None

    def scan(self, paths, heuristics=None):
        # override scan as comodo uses only absolute paths, we need to convert
        # provided paths to absolute paths first
        paths = os.path.abspath(paths)
        return super(ComodoCAVL, self).scan(paths, heuristics)
