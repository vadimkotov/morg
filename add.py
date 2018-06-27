import sys
import os
import argparse

from core import database
from core import extractors

import logging
logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)




class Organizer:

    def __init__(self, session, extractor=None):
        self.session = session
        self.extractor = extractor
        
    def add_file(self, path):
        logging.debug("Scanning file: {}".format(path))
        sha256 = os.path.basename(path)

        file_ = database.file_by_sha256(self.session, sha256)
        if not file_:
            logging.debug("File doesn't exist, adding...")
            file_ = database.add_file(self.session, sha256)
        
        logging.debug("File id = {}".format(file_.id))

        for e_name, func in extractors.ALL.items():
            if self.extractor and self.extractor != e_name:
                continue
            
            logging.debug("Running: {}".format(e_name))
            func(self.session, path, file_)


        
    def add_dir(self, dir_):
        logging.info("Walking directory: {}".format(dir_))

        for root, dirs, files in os.walk(dir_):
            for filename in files:
                self.add_file(os.path.join(root, filename))
                # sys.exit()

            
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--extractor", help="Specific extractor")
    # parser.add_argument("-l", "--list", action="store_true", help="List available extractors")
    parser.add_argument("source", help="File or folder to add")
    parser.add_argument("database", help="Database connection string")
    args = parser.parse_args()

    
    src = args.source

    org = Organizer(database.connect(args.database), args.extractor)
    
    
    if os.path.isfile(src):
        org.add_file(src)
    elif os.path.isdir(src):
        org.add_dir(src)
        
if __name__ == "__main__":
    main()
