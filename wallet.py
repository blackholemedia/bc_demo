"""
Module docstring.
"""

import sys
import getopt
import hashlib
import base58
import pickle

from fastecdsa import curve, keys

from common import int_to_bytes
from constants import VERSION, ADDRESS_CHECKSUM_LEN
from logger import logging


class Wallet(object):

    def __init__(self):
        self.private_key, self.public_key = self.new_key_pair()

    def new_key_pair(self):
        private_key = keys.gen_private_key(curve.P256)
        pub_key = keys.get_public_key(private_key, curve.P256)
        pub_key = b''.join([int_to_bytes(pub_key.x), int_to_bytes(pub_key.y)])
        return private_key, pub_key

    def get_address(self):
        pubkey_hash = self.hash_pubkey()
        versioned_payload = b''.join([int_to_bytes(VERSION) + pubkey_hash.encode('utf-8')])
        checksum = self.check_sum(versioned_payload)
        full_payload = b''.join([versioned_payload, checksum])
        address = base58.b58encode(full_payload)
        return address

    def hash_pubkey(self):
        public_hash = hashlib.sha256(self.public_key).hexdigest()
        ripemd_hasher = hashlib.new('ripemd160')
        ripemd_hasher.update(public_hash.encode('utf-8'))
        return ripemd_hasher.hexdigest()

    @staticmethod
    def check_sum(payload: bytes):
        hash_1 = hashlib.sha256(payload).hexdigest()
        hash_2 = hashlib.sha256(hash_1.encode('utf-8')).hexdigest()
        return hash_2.encode('utf-8')[:ADDRESS_CHECKSUM_LEN]


class Wallets(object):

    def __init__(self):
        self.wallets = self.load_wallets_file()

    @staticmethod
    def load_wallets_file(wallet_file='./wallets.dat'):  # todo encrypt
        try:
            with open(wallet_file, 'rb') as f:
                return pickle.loads(f.read())
        except IOError as ex:
            msg = 'No wallets file found'
            logging.warning(msg)
            return {}

    def create_wallet(self):
        new_wallet = Wallet()
        address = new_wallet.get_address()
        self.wallets.update({address: Wallet})
        return address

    def get_wallet(self, address) -> Wallet:
        return self.wallets.get(address)

    def save_wallets_file(self, wallet_file='./wallets.dat'):  # todo encrypt
        with open(wallet_file, 'wb') as f:
            return f.write(pickle.dumps(self.wallets))


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
