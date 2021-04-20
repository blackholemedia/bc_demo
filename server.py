"""
Node server implementation.
"""

import sys
import getopt
import socket

from base import BlockChain
from common import int_to_bytes
from constants import CENTRAL_NODE, HOST
from logger import logging


class Server(object):

    def __init__(self, node_id, miner_address, host=HOST):
        node_address = 'localhost:{}'.format(node_id)
        print('Node address: {}'.format(node_address))
        bc = BlockChain(node_id)
        if node_id != CENTRAL_NODE:
            self.send_version(bc)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, node_id))
            s.listen(10)
            try:
                while True:
                    conn, addr = s.accept()
                    with conn:
                        print('Connected by', addr)
                        while True:
                            data = conn.recv(4)
                            if not data:
                                break
                            conn.sendall(data)
            except KeyboardInterrupt as ex:
                pass

    def send_version(self, bc: BlockChain):
        pass


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
