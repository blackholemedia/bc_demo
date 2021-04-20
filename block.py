"""
Block implementation.
"""

import sys
import getopt
import hashlib
import pickle
import time

from common import int_to_bytes, now
from merkle import MerkleTree


class Block(object):

    def __init__(self, pre_hash: str, txns: list, target_bit: int):
        self.timestamp = now()
        self.pre_hash = pre_hash
        self.transactions = txns
        self.target_bit = target_bit
        self.nonce, self.hash = self.proof_of_work()

    def proof_of_work(self, nonce=0):
        target = 1 << (256 - self.target_bit)
        print("Mining the block containing txn {}".format(self.transactions[0].txn_id))
        s = time.time()
        txn_hash = self._hash_transactions()
        while nonce < (1 << 64):
            hash_data = self._prepare_data(nonce, txn_hash)
            result = hashlib.sha256(hash_data).hexdigest()
            if int(result, 16) < target:
                print(result)
                break
            else:
                nonce += 1
        print('Mining cost {} seconds'.format(time.time() - s))
        return nonce, result

    def _prepare_data(self, nonce, txn_hash):
        return b"".join(
            [
                int_to_bytes(self.timestamp),
                int_to_bytes(self.target_bit),
                int_to_bytes(nonce),
                bytes.fromhex(self.pre_hash),
                txn_hash
            ]
        )

    def _hash_transactions(self):
        txn_ids = [i.txn_id.encode('utf-8') for i in self.transactions]
        return MerkleTree(txn_ids).root.data

    def serialize(self):
        return pickle.dumps(self)


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
