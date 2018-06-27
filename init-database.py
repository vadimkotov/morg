import sys

from core import database

def main():
    if len(sys.argv) != 2:
        exit("Usage: {} <name>".format(sys.argv[0]))

    database.init_db(sys.argv[1])


if __name__ == "__main__":
    main()
