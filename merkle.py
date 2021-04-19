"""
Module docstring.
"""

import sys
import getopt
import hashlib
from logger import logging


class MerkleNode(object):

    def __init__(self, data, left=None, right=None):
        if not left and not right:
            self.data = hashlib.sha256(data).hexdigest().encode('utf-8')
        else:
            pre_hash = b''.join([left.data, right.data])
            self.data = hashlib.sha256(pre_hash).hexdigest().encode('utf-8')
        self.left = left
        self.right = right


class MerkleTree(object):

    def __init__(self, data: list):
        if not data:
            logging.error('Empty list is not allowed')
            sys.exit(1)
        if len(data) % 2 != 0:
            data.append(data[-1])
        self.root = self.create_tree(data)

    def create_tree(self, data: list):
        length = len(data)
        if length == 2:
            left = MerkleNode(data[0])
            right = MerkleNode(data[1])
            return MerkleNode(data=None, left=left, right=right)
        r = []
        for i in range(0, length, 2):
            left = MerkleNode(data[i])
            right = MerkleNode(data[i+1])
            r.append(MerkleNode(data=None, left=left, right=right))
        if length % 2 != 0:
            r.append(data[-1])

        return self.create_tree(r)


class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg


def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "hpcf:t:a:b:", ["help", "print", "create_wallet", "from=", "to=", "amount=", 'balance='])
            # short: h means switch, o means argument required; long: help means switch, output means argument required
        except getopt.error as msg:
            raise Usage(msg)
        # more code, unchanged
    except Usage as err:
        print(sys.stderr, err.msg)
        print(sys.stderr, "for help use --help")
        return 2


if __name__ == "__main__":
    sys.exit(main())
