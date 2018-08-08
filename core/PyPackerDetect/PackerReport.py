from __future__ import print_function

import simplejson

from Utils import *


def default_outfn(msg):
    print(msg)

class PackerReport(object):
    def __init__(self, name):
        self.name = name
        self.detections = 0
        self.suspicions = 0
        self.failed = False
        self.error = ""
        self.logs = []

    def IndicateDetection(self, message):
        self.logs.append("DET - %s" % message)
        self.detections += 1

    def IndicateSuspicion(self, message):
        self.logs.append("SUS - %s" % message)
        self.suspicions += 1

    def IndicateParseFailed(self, message):
        self.error = message
        self.failed = True

    def GetDetections(self):
        return self.detections

    def GetSuspicions(self):
        return self.suspicions

    def GetParseFailed(self):
        return self.failed


    def Print(self, outfn=default_outfn):
        outfn("Packer report for: %s" % self.name)
        if (self.failed):
            outfn("\tError: %s" % self.error)
        else:
            outfn("\tDetections: %d" % self.detections)
            outfn("\tSuspicions: %d" % self.suspicions)
            outfn("\tLog:")

            for log in self.logs:
                outfn("\t\t%s" % log)

    def GetJson(self):
        return {
                "failed": self.failed,
                "error": self.error,
                "detections": self.detections,
                "suspicions": self.suspicions,
                "logs": self.logs
        }
