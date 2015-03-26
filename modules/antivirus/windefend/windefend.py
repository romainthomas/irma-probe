#
# Copyright (c) 2013-2014 QuarksLab.
# This file is part of IRMA project.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the top-level directory
# of this distribution and at:
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# No part of the project, including this file, may be copied,
# modified, propagated, or distributed except according to the
# terms contained in the LICENSE file.

import logging
import re
import os

from glob import glob
from subprocess import Popen, PIPE
from lib.common.utils import to_unicode
from modules.antivirus.base import Antivirus

log = logging.getLogger(__name__)


class WinDefender(Antivirus):

    # ==================================
    #  Constructor and destructor stuff
    # ==================================

    def __init__(self, *args, **kwargs):
        # class super class constructor
        super(WinDefender, self).__init__(*args, **kwargs)
        # set default antivirus information
        self._name = "Windows Defender Anti-Virus"
        # scan tool variables
        self._scan_args = (
            "-Scan "
            "-ScanType 3 "  # File and directory custom scan
            "-DisableRemediation "
            "-File "    # Indicates the file or directory  to be scanned
        )
        self._scan_retcodes = {
            self.ScanResult.CLEAN: lambda x: x in [0],
            self.ScanResult.INFECTED: lambda x: x in [2],
            self.ScanResult.ERROR: lambda x:
                not self._scan_retcodes[self.ScanResult.CLEAN](x) and
                not self._scan_retcodes[self.ScanResult.INFECTED](x),
        }
        self._scan_patterns = [
            re.compile(r"ThreatName\s+:\s+(?P<name>.+)\s+\((?P<file>.+)\)",
                       re.IGNORECASE)
        ]

    # ==========================================
    #  Antivirus methods (need to be overriden)
    # ==========================================

    def get_version(self):
        """return the version of the antivirus"""
        result = None
        try:
            files = glob("{path}/Microsoft/Windows Defender/"
                         "Support/MPDetection-*"
                         "".format(path=os.environ.get('PROGRAMDATA', '')))
            if files:
                files = os.path.normpath(files.pop())
                with open(files, 'r') as fdesc:
                    for line in fdesc:
                        line = line.decode('utf-16-be', 'ignore')
                        # ignore 25 first characters which is the timestamp
                        matches = re.search(r'(?P<version>\d+(\.\d+)+)',
                                            line[25:], re.IGNORECASE)
                        if matches:
                            result = matches.group('version').strip()
                            break
        except:
            pass
        return result

    def get_database(self):
        """return list of files in the database"""
        search_paths = map(lambda x:
                            "{path}/Microsoft/Windows Defender/"
                            "Definition Updates/Default/".format(path=x),
                            [os.environ.get('PROGRAMDATA', '')])
        results = self.locate('*', search_paths, syspath=False)
        return results if results else None

    def get_scan_path(self):
        """return the full path of the scan tool"""
        scan_bin = "MpCmdRun.exe"
        scan_paths = map(lambda x: "{path}/Windows Defender/".format(path=x),
                         [os.environ.get('PROGRAMFILES', ''),
                          os.environ.get('PROGRAMFILES(X86)', '')])
        paths = self.locate(scan_bin, scan_paths)
        return paths[0] if paths else None

    ##########################################################################
    # specific scan method
    ##########################################################################

    def check_scan_results(self, paths, results):
        retcode, stdout, stderr = results[0], None, results[2]
        cmd = 'Get-MpThreat|Where Resources -match %s|select ThreatName|fl'
        cmd = cmd % os.path.basename(paths)
        # NOTE: we run Popen here instead of using self.run_cmd() because of
        #       a known bug with self.run_cmd() - for the known bug, see
        #       issue at github.com/quarkslab/irma-probe/issues/39
        pd = Popen(['powershell.exe', '-Command', cmd ],
                   stdout=PIPE, stderr=PIPE)
        raw_stdout, _ = map(lambda x: x.strip() if x.strip() else None,
                                 pd.communicate())
        # recreate a custom formatted result for the regular expression
        results = retcode, "%s (%s)" % (raw_stdout, paths), stderr
        return super(WinDefender, self).check_scan_results(paths, results)
