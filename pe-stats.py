import sys
import os
import argparse
import csv
import pefile

from core import database
from core import extractors
from core import utils

import logging
logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.ERROR)

from  sqlalchemy.sql.expression import func

from Queue import Queue
from threading import Thread


IN_QUEUE = Queue()
OUT_QUEUE = Queue()



def strip_nulls(str_):
    while str_[-1] == "\00":
        str_ = "".join(list(str_)[:-1])
        if not str_:
            return "<empty_string>"
    return str_


def parser_thread():
    while True:
        path = IN_QUEUE.get()
        pe = pefile.PE(path)
        OUT_QUEUE.put(pe)
        IN_QUEUE.task_done()
        

def out_thread(extractor):
    while True:
        pe = OUT_QUEUE.get()
        extractor.analyze(pe)
        OUT_QUEUE.task_done()
        


"""
def get_sections(pe):
    for section in pe.sections:
        print (strip_nulls(section.Name),
               hex(section.VirtualAddress),
               hex(section.Misc_VirtualSize),
               section.SizeOfRawData,
               hex(section.Characteristics),
               section.NumberOfRelocations)
"""

class Sections:
    def __init__(self, total=None):
        self.names = {}
        self.n_processed = 0.0
        self.total = total
        
    def analyze(self, pe):
        self.n_processed += 1
        
        for section in pe.sections:

            name = strip_nulls(section.Name)
            if name not in self.names:
                self.names[name] = 0
            self.names[name] += 1

        if self.total:
            utils.progress(self.n_processed, self.total)

    def export(self, path):
        with open(path, "wb") as fd:
            writer = csv.writer(fd)
            for name, count in sorted(self.names.items(), key=lambda x: x[1], reverse=True):
                percentage = count / self.n_processed * 100
                writer.writerow((name, percentage))
        
def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("size", type=int, help="Sample size")
    parser.add_argument("root", help="Root of data storage")
    parser.add_argument("database", help="Database connection string")
    parser.add_argument("outfile", help="File to output data")
    args = parser.parse_args()

    session = database.connect(args.database)

    n = args.size
        
    for entry in session.query(database.PE).filter_by(dotnet=0).order_by(func.random()).limit(n):
        
        sha256 = entry.file.sha256
        dir_ = utils.hash_to_dir(sha256, args.root)
        path = os.path.join(dir_, sha256)

        logging.debug("Analyzing {}".format(path))

        # TODO: move to utils or something
        upx_rec = session.query(database.UPX).filter_by(file_id=entry.file.id).first()
        if upx_rec:
            logging.debug("upx: UPXed binary")
            decompressed = path + extractors.EXT_UNUPXED
            if upx_rec.result and os.path.exists(decompressed):
                logging.debug("upx: using decompressed binary: {}".format(decompressed))
                path = decompressed

        IN_QUEUE.put(path)
        

    for i in range(20):
        utils.start_daemon(parser_thread)

        
    extractor = Sections(n)
    utils.start_daemon(out_thread, dict(extractor=extractor))

    IN_QUEUE.join()
    OUT_QUEUE.join()

    extractor.export(args.outfile)
    session.close()
    
            
if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        print "Exiting..."
        
