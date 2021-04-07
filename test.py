"""
Module docstring.
"""

import sys
import getopt
import hashlib


class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg


def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "ho:", ["help", "output="])  # short: h means switch, o means argument
            # required; long: help means switch, output means argument required
            data1 = "I like donuts"
            data2 = "I like donutsca07ca"
            targetBits = 24
            target = 1
            target <<= (256 - targetBits)
            print(hashlib.sha256(data1.encode('utf-8')).hexdigest())
            print(hex(target))
            print(hashlib.sha256(data2.encode('utf-8')).hexdigest())
        except getopt.error as msg:
            raise Usage(msg)
        # more code, unchanged
    except Usage as err:
        print(sys.stderr, err.msg)
        print(sys.stderr, "for help use --help")
        return 2


if __name__ == "__main__":
    sys.exit(main())
