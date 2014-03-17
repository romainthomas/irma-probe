import logging

from modules.antivirus.kaspersky import Kaspersky
from probes.antivirus.antivirus import AntivirusProbe


log = logging.getLogger(__name__)

class KasperskyProbe(AntivirusProbe):
    
    ##########################################################################
    # plugin metadata
    ##########################################################################

    _plugin_name = "Kaspersky"
    _plugin_version = "0.0.0"
    _plugin_description = "Antivirus plugin for Kaspersky Antivirus"

    ##########################################################################
    # constructor and destructor stuff
    ##########################################################################

    def __init__(self, conf=None, **kwargs):
        # call super classes constructors
        super(KasperskyProbe, self).__init__(conf, **kwargs)
        self._module = Kaspersky()
