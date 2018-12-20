# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import hashlib
import json
import math
import os
import struct
import time
import threading

try:
  import urllib2
except:
  import urllib.request as urllib2

from . import base58
from . import bootstrap
from . import ecc
from . import key
from . import piecewise

from .hash import sha1, sha256, sha256d, ripemd160, hash160
from binascii import hexlify

__all__ = [
    'base58', 'ecc', 'key', 'piecewise',
    'sha1', 'sha256', 'sha256d', 'ripemd160', 'hash160',
    'get_version', 'make_version', 'default_data_dir'
]

def x11(data):
    raise NotImplemented()


# Formatting Helpers

def publickey_hash(pub_key):
    pubHash = hashlib.sha512(pub_key).digest()
    s1 = hashlib.new('ripemd160',pubHash[:32]).digest()
    s2 = hashlib.new('ripemd160',pubHash[32:]).digest()
    return hashlib.sha256(s1+s2).digest()


# Block Header Helpers

def get_block_header(version, link_no, prev_block, merkle_root, timestamp, bits, nonce):  # total 84 bytes
    return struct.pack('<II32s32sIII', version, link_no, prev_block, merkle_root, timestamp, bits, nonce)

def get_block_header2(version, link_no, prev_block, merkle_root, timestamp, bits):  # total 80 bytes
    return struct.pack('<II32s32sII', version, link_no, prev_block, merkle_root, timestamp, bits)

# https://en.bitcoin.it/wiki/Protocol_specification#Merkle_Trees
def get_merkle_root(transactions):
    branches = [t.hash for t in transactions]

    while len(branches) > 1:
        if (len(branches) % 2) == 1:
            branches.append(branches[-1])

        branches = [sha256d(a + b) for (a, b) in zip(branches[0::2], branches[1::2])]

    return branches[0]


# Protocl Version Helpers

def get_version(version):
     major = version // 1000000
     minor = (version // 10000) % 100
     revision = (version // 100) % 100
     build = version % 100
     return (major, minor, revision, build)

def make_version(major, minor, revision, build):
    if not ((0 <= minor < 100) and (0 <= revision < 100) and (0 <= build < 100)):
        raise ValueError('minor, revision and build must be in the range [0, 99]')
    return (major * 1000000) + (minor * 10000) + (revision * 100) + build


# File Helpers

def default_data_dir():
    return os.path.expanduser('~/.newbitcoin/data')
