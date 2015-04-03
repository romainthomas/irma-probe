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

import os
import sys

from .windefend import WinDefender
from ..interface import AntivirusPluginInterface

from lib.plugins import PluginBase, PluginLoadError
from lib.plugins import PlatformDependency

from lib.irma.common.utils import IrmaProbeType


class WinDefenderPlugin(PluginBase, WinDefender, AntivirusPluginInterface):

    # =================
    #  plugin metadata
    # =================

    _plugin_name_ = "WinDefender"
    _plugin_author_ = "IRMA (c) Quarkslab"
    _plugin_version_ = "1.0.0"
    _plugin_category_ = IrmaProbeType.antivirus
    _plugin_description_ = "Plugin for Windows Defender"
    _plugin_dependencies_ = [
        PlatformDependency('win32')
    ]

    @classmethod
    def verify(cls):
        """
        MpCmdRun.exe with -ScanType 3 argument only supported
        on Win8.1 and later
        Win7sp1 (major=6, minor=1)
        Win8.1  (major=6, minor=2)
        """
        (major, minor, _, _, _) = sys.getwindowsversion()
        if major < 6 or (major >= 6 and minor < 2):
            raise PluginLoadError("{0}: verify() failed because "
                                  "This Windows version is not yet supported"
                                  "".format(cls.__name__))
        # create an instance
        module = WinDefender()
        path = module.scan_path
        del module
        # perform checks
        if not path or not os.path.exists(path):
            raise PluginLoadError("{0}: verify() failed because "
                                  "MpCmdRun.exe executable was not found."
                                  "".format(cls.__name__))

    # =============
    #  constructor
    # =============

    def __init__(self):
        self.module = WinDefender()
