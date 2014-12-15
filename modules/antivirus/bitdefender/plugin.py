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

from .bitdefender import BitdefenderForUnices
from ..interface import AntivirusPluginInterface

from lib.plugins import PluginBase
from lib.plugins import BinaryDependency, PlatformDependency
from lib.irma.common.utils import IrmaProbeType


class BitdefenderForUnicesPlugin(PluginBase, BitdefenderForUnices,
                                 AntivirusPluginInterface):

    # =================
    #  plugin metadata
    # =================

    _plugin_name_ = "BitdefenderForUnices"
    _plugin_author_ = "IRMA (c) Quarkslab"
    _plugin_version_ = "1.0.0"
    _plugin_category_ = IrmaProbeType.antivirus
    _plugin_description_ = "Plugin for Bitdefender Antivirus Scanner " \
                           "for Unices"
    _plugin_dependencies_ = [
        PlatformDependency('linux'),
        BinaryDependency(
            'bdscan',
            help='bdscan executable is provided by '
                 'Bitdefender Antivirus Scanner for Unices.'
        ),
    ]

    # =============
    #  constructor
    # =============

    def __init__(self):
        # load default configuration file
        self.module = BitdefenderForUnices()
