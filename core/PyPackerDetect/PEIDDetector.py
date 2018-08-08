import os
import peutils

from Utils import *
from PackerDetector import *

DEPS_PATH = "core/PyPackerDetect/deps/peid"

class PEIDDetector(PackerDetector):
    def __init__(self, config):

        super(PEIDDetector, self).__init__(config)
        
        if (self.config["UseLargePEIDDatabase"]):
            self.signatures = peutils.SignatureDatabase(os.path.join(DEPS_PATH, 'signatures_long.txt'))
        else:
            self.signatures = peutils.SignatureDatabase(os.path.join(DEPS_PATH, 'signatures_short.txt'))


    def Run(self, pe, report):
        if (not self.config["CheckForPEIDSignatures"]):
            return

        matches = self.signatures.match_all(pe, ep_only=self.config["OnlyPEIDEntryPointSignatures"])
        if (not matches):
            return
    
        for match in matches:
            report.IndicateDetection("Found PEID signature: %s" % match)
