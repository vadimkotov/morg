from Utils import *

class PackerDetector(object):
    def __init__(self, config):
        self.config = config

    def Run(self, pe, report):
        raise NotImplementedError
