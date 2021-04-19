"""
Module docstring.
"""

import sys
import getopt
import time

import redis


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
        except getopt.error as msg:
            raise Usage(msg)
        # more code, unchanged
    except Usage as err:
        print(sys.stderr, err.msg)
        print(sys.stderr, "for help use --help")
        return 2


def now(unit='ms'):
    epoch = time.time()
    if unit == 'ms':
        epoch *= 1000
    if unit == 'ns':
        epoch *= 1000000
    return int(epoch)


def int_to_bytes(num: int):
    return num.to_bytes((num.bit_length() + 7) // 8, 'big')


def bytes_to_int(num: bytes):
    return int.from_bytes(num, 'big')


def conn_redis(host='localhost', port=6379):
    return redis.Redis(host=host, port=port)


def clear_bucket(connection: redis.Redis, bucket_name):
    if not connection.exists(bucket_name):
        return
    for k, v in connection.hscan_iter(bucket_name):
        connection.hdel(bucket_name, k)


if __name__ == "__main__":
    sys.exit(main())
