"""
Module docstring.
"""

import sys
import getopt
import hashlib

import json

from common import now, int_to_bytes, conn_redis
from constants import TARGET_BIT, BLOCKS_BUCKET_NAME


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

    def serialize(self):
        return json.dumps(
            {
                'timestamp': self.timestamp,
                'pre_hash': self.pre_hash,
                'hash': self.hash,
                'nonce': self.nonce,
                'data': self.data,
                'target_bit': self.target_bit
            }
        )


class BlockChain(object):

    def __init__(self):
        self.target_bits = TARGET_BIT
        self.conn = conn_redis()
        if self.conn.exists(BLOCKS_BUCKET_NAME):
            self.tip = self.conn.hget(BLOCKS_BUCKET_NAME, 'l').decode('utf-8')
        else:
            genesis_block = self.create_genesis_block()
            self.conn.hset(BLOCKS_BUCKET_NAME, genesis_block.hash, genesis_block.serialize())
            self.conn.hset(BLOCKS_BUCKET_NAME, 'l', genesis_block.hash)
            self.tip = genesis_block.hash

    def create_genesis_block(self):
        pre_hash = ''
        data = 'Genesis Block'
        return Block(pre_hash, data, self.target_bits)

    def add_block(self, data):
        pre_hash = self.tip
        new_block = Block(pre_hash, data, self.target_bits)
        self.conn.hset(BLOCKS_BUCKET_NAME, new_block.hash, new_block.serialize())
        self.conn.hset(BLOCKS_BUCKET_NAME, 'l', new_block.hash)
        self.tip = new_block.hash

    def chain_iterator(self):
        current_hash = self.tip
        while current_hash:
            current_block = json.loads(self.conn.hget(BLOCKS_BUCKET_NAME, current_hash))
            yield current_block
            current_hash = current_block.get('pre_hash')


class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg


def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "hpa:", ["help", "print", "add_block="])  # short: h means switch, o means argument
            # required; long: help means switch, output means argument required
            bc = BlockChain()
            for opt, opt_val in opts:
                if opt in ("-h", "--help"):
                    print('-p, --print: print block chain\n-a --add_block: add block')
                    sys.exit()
                if opt in ('-p', '--print'):
                    for i in bc.chain_iterator():
                        print('timestamp: {}\npre_hash: {}\ndata: {}\nhash: {}\nnonce: {}\n'.format(i['timestamp'],
                                                                                                    i['pre_hash'],
                                                                                                    i['data'],
                                                                                                    i['hash'],
                                                                                                    i['nonce']))
                    continue
                if opt in ('-a', '--add_block'):
                    bc.add_block(opt_val)

            # bc.add_block("Send 1 BTC to Ivan")
            # bc.add_block("Send 2 more BTC to Ivan")

                # print('timestamp: {}\npre_hash: {}\ndata: {}\nhash: {}\nnonce: {}'.format(i.timestamp, i.pre_hash,
                #                                                                           i.data, i.hash, i.nonce))
        except getopt.error as msg:
            raise Usage(msg)
        # more code, unchanged
    except Usage as err:
        print(sys.stderr, err.msg)
        print(sys.stderr, "for help use --help")
        return 2


if __name__ == "__main__":
    sys.exit(main())
