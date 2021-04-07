"""
Module docstring.
"""

import sys
import getopt
import hashlib

from common import now, int_to_bytes
from constants import TARGET_BIT


class Block(object):

    def __init__(self, pre_hash: str, data: str, target_bit: int):
        self.timestamp = now()
        self.pre_hash = pre_hash
        self.data = data
        self.target_bit = target_bit
        self.nonce, self.hash = self.proof_of_work()

    # def set_hash(self):
    #     hash_data = str(self.timestamp) + str(self.pre_hash) + self.data
    #     result = hashlib.sha256(hash_data.encode('utf-8'))
    #     return result.hexdigest()

    def proof_of_work(self, nonce=0):
        target = 1 << (256 - self.target_bit)
        print("Mining the block containing {}".format(self.data))
        while nonce < (1 << 64):
            hash_data = self._prepare_data(nonce)
            result = hashlib.sha256(hash_data).hexdigest()
            if int(result, 16) < target:
                print(result)
                break
            else:
                nonce += 1
        return nonce, result

    def _prepare_data(self, nonce):
        return b"".join(
            [
                int_to_bytes(self.timestamp),
                int_to_bytes(self.target_bit),
                int_to_bytes(nonce),
                bytes.fromhex(self.pre_hash),
                self.data.encode('utf-8')
            ]
        )


class BlockChain(object):

    def __init__(self):
        self.target_bits = TARGET_BIT
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        pre_hash = ''
        data = 'Genesis Block'
        return Block(pre_hash, data, self.target_bits)

    def add_block(self, data):
        pre_hash = self.chain[-1].hash
        self.chain.append(Block(pre_hash, data, self.target_bits))


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
            bc = BlockChain()
            bc.add_block("Send 1 BTC to Ivan")
            bc.add_block("Send 2 more BTC to Ivan")
            for i in bc.chain:
                print('timestamp: {}\npre_hash: {}\ndata: {}\nhash: {}\nnonce: {}'.format(i.timestamp, i.pre_hash,
                                                                                          i.data, i.hash, i.nonce))
        except getopt.error as msg:
            raise Usage(msg)
        # more code, unchanged
    except Usage as err:
        print(sys.stderr, err.msg)
        print(sys.stderr, "for help use --help")
        return 2


if __name__ == "__main__":
    sys.exit(main())
