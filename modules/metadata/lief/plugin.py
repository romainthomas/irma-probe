#
# Copyright (c) 2013-2015 QuarksLab.
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

import re
import os
import sys
import logging

from datetime import datetime

from lib.common.utils import timestamp
from lib.plugins import PluginBase
from lib.plugins import ModuleDependency
from lib.plugin_result import PluginResult
from lib.irma.common.utils import IrmaProbeType
from lib.plugins.exceptions import PluginLoadError

class LiefAnalyzerPlugin(PluginBase):

    class LiefAnalyzerResult:
        ERROR = -1
        FAILURE = 0
        SUCCESS = 1

    # =================
    #  plugin metadata
    # =================
    _plugin_name_ = "LIEF"
    _plugin_author_ = "Romain Thomas"
    _plugin_version_ = "1.0.0"
    _plugin_category_ = IrmaProbeType.metadata
    _plugin_description_ = "Plugin using LIEF to analyze binaries"
    _plugin_dependencies_ = [
        ModuleDependency(
            'lief',
            help='See requirements.txt for needed dependencies'
        ),
    ]
    _mimetype_regexp = None

    # =============
    #  constructor
    # =============

    def __init__(self):
        module = sys.modules['modules.metadata.lief.analyzer'].LiefAnalyzer
        self.module = module()

    def can_handle(self, mimetype):
        return re.search('ELF', mimetype, re.IGNORECASE) is not None


    # ==================
    #  probe interfaces
    # ==================
    def analyze(self, filename):
        # check parameters
        if not filename:
            raise RuntimeError("filename is invalid")
        # check if file exists
        mimetype = None
        if os.path.exists(filename):
            # guess mimetype for file
            magic = sys.modules['lib.common.mimetypes'].Magic
            mimetype = magic.from_file(filename)
        else:
            raise RuntimeError("file does not exist")
        result = None
        if mimetype and re.match('ELF', mimetype):
            result = self.module.analyze(filename)
        else:
            logging.warning("{0} not yet handled".format(mimetype))

        return result
    def run(self, paths):
        results = PluginResult(name=type(self).plugin_name,
                                type=type(self).plugin_category,
                                version=None)
        try:
            started = timestamp(datetime.utcnow())
            response = self.analyze(filename=paths)
            stopped = timestamp(datetime.utcnow())

            results.duration = stopped - started
            # update results
            if not response:
                results.status = self.LiefAnalyzerResult.FAILURE
                results.results = "ERROR"
            else:
                results.status = self.LiefAnalyzerResult.SUCCESS
                results.results = response
        except Exception as e:
            results.status = self.LiefAnalyzerResult.ERROR
            results.results = str(e)
        return results
