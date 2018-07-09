import sys
import os
import argparse
import csv
import pefile


from core import database
from core import stats
from core import utils
from core import extractors

import logging
logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.ERROR)

from  sqlalchemy.sql.expression import func

        

        
def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("extractor", help="Name of extractor")
    parser.add_argument("size", type=int, help="Sample size")
    parser.add_argument("root", help="Root of data storage")
    parser.add_argument("database", help="Database connection string")
    parser.add_argument("outfile", help="File to output data")
    args = parser.parse_args()

    session = database.connect(args.database)

    n = args.size

    Extractor = stats.ALL.get(args.extractor)

    if not Extractor:
        logging.error("Extractor {} doesn't exist".format(args.extractor))
        return

    extractor = Extractor(session, n)
        
    for entry in session.query(database.PE).filter_by(dotnet=0).order_by(func.random()).limit(n):
        
        sha256 = entry.file.sha256
        dir_ = utils.hash_to_dir(sha256, args.root)
        path = os.path.join(dir_, sha256)

        logging.debug("Analyzing {}".format(path))

        # Virus total check
        
        vt_entry = database.query_one(session, database.VirusTotal, entry.file)
        if not vt_entry:
            logging.debug("Doesn't have a virus total entry")
            continue

        vt_info = utils.unpack(vt_entry.data)

        if not stats.is_confirmed_malware(vt_info):
            logging.debug("Not confirmed malware")
            continue
        # End of Virus total check

        
        
        # TODO: move to utils or something
        upx_rec = session.query(database.UPX).filter_by(file_id=entry.file.id).first()
        if upx_rec:
            logging.debug("upx: UPXed binary")
            decompressed = path + extractors.EXT_UNUPXED
            if upx_rec.result and os.path.exists(decompressed):
                logging.debug("upx: using decompressed binary: {}".format(decompressed))
                path = decompressed

        extractor.analyze(entry.file)
        

    extractor.export(args.outfile)
    session.close()
    
            
if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        print "Exiting..."
        
