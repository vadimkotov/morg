import sys
import os
import argparse

from core import database
from core import extractors
from core import utils

import logging
logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

from Queue import Queue



IN_QUEUE = Queue()
OUT_QUEUE = Queue()


def ext_thread():
    while True:
        extractor, path, file_ = IN_QUEUE.get()
        entry = extractor(path, file_)
        
        if entry:
            OUT_QUEUE.put(entry)
            
        IN_QUEUE.task_done()
        
    
def out_thread(db_str, total):
    bulk_size = 20
    session = database.connect(db_str)
    cnt = 0
    while True:
        entry = OUT_QUEUE.get()
        session.add(entry)
        # session.commit()
        cnt += 1
        if cnt > 0 and cnt % 20 == 0:
            session.commit()
            
        utils.progress(cnt, total)
        
        OUT_QUEUE.task_done()
        
    
class PEAnalyzer:
    def __init__(self, root, session, extractor):
        self.root = root
        self.session = session
        self.extractor = extractor


    def run(self):
        cnt = 0
        for entry in self.session.query(database.PE).filter_by(dotnet=0).all():
            sha256 = entry.file.sha256
            dir_ = utils.hash_to_dir(sha256, self.root)
            path = os.path.join(dir_, sha256)

            
            # if database.record_exists(self.session, database.IDA_CFG, entry.file):
            table = extractors.TABLES.get(self.extractor)
            if not table:
                logging.error("Couldn't find table refferred as {}".format(self.extractor))
                sys.exit()
                
            if database.record_exists(self.session, table, entry.file):
                logging.debug("e_{}: record exists".format(self.extractor))
                continue

            # TODO: move to utils or something, that whole snipped is used in pe-stats.py
            upx_rec = self.session.query(database.UPX).filter_by(file_id=entry.file.id).first()
            if upx_rec:
                
                decompressed = path + extractors.EXT_UNUPXED
                if upx_rec.result and os.path.exists(decompressed):
                    logging.debug("upx: using decompressed binary: {}".format(decompressed))
                    path = decompressed
            
            # logging.debug("Adding to queue: {}".format(path))
            func = extractors.ALL.get(self.extractor)
            
            if func:
                # func(self.session, path, entry.file)
                IN_QUEUE.put((func, path, entry.file))

            
            cnt += 1
            # if cnt > 10:
            #     break
        return cnt

            
def main():
        
    parser = argparse.ArgumentParser()
    parser.add_argument("extractor", help="Extractor")
    parser.add_argument("root", help="Root of data storage")
    parser.add_argument("database", help="Database connection string")
    args = parser.parse_args()

    session = database.connect(args.database)

    analyzer = PEAnalyzer(args.root, session, args.extractor)
    total = analyzer.run()
    session.close()
    
    for i in range(10):
        utils.start_daemon(ext_thread)

    utils.start_daemon(out_thread, dict(db_str=args.database, total=total))

    IN_QUEUE.join()
    OUT_QUEUE.join()
            
if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        print "Exiting..."
        
