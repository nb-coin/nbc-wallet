# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

import struct

from .. import util
from .. import protocol

from . import coin

__all__ = ['Newbitcoin']

_PAY2MINER = b'\x76\xb8\xb9\x88\xac'  # DUP OP_HASH512 OP_MINERHASH OP_EQUALVERIFY OP_CHECKSIG

import codecs
_decodeHex = codecs.getdecoder("hex_codec")

def decodeHex(s):  # avoid using 'ff'.decode('hex') that not supported in python3
  return _decodeHex(s)[0]

class Newbitcoin(coin.Coin):
  COINBASE_MATURITY = 8
  WEB_SERVER_ADDR = 'https://api.nb-coin.com'
  
  name    = "newbitcoin"
  symbols = ['NBC']         # all symbols
  symbol  = symbols[0]      # primary symbol
  
  mining_coin_type   = b'\x00'
  currency_coin_type = b'\x00'
  protocol_version   = 0
  
  magic = b'\xf9\x6e\x62\x63'
  
  raw_seed = ('raw%.pinp.io',20303)    # tcp listen port is 20303
  
  genesis_version = 1
  genesis_block_hash = decodeHex(b'f84316c0637446c08e31bbc135e74a7f9572b9615bab5d8d52bca03835000000')
  genesis_merkle_root = decodeHex(b'923615068cea108e04af957754aca4540ee9656d427c76f768f8d8ea8ed308f2')
  genesis_timestamp = 1546500212
  genesis_bits = 2500
  genesis_miner = decodeHex(b'd20d21e17681d6a984508f4138592dfa6b592e11e982aaad2af7627440a691d6')
  genesis_nonce = 154234690
  genesis_signature = decodeHex(b'3046022100870f7223f279e14cccd068e5f55a8ae00eeab32bff38a5db60891303406521860221008d9a682954dc9f2318b6845e5dd01fadb94b8f90c143d7835cf22a9b8437ae8900')
  genesis_txn = protocol.Txn( 1,
      [protocol.TxnIn(protocol.OutPoint(b'\x00'*32,0xffffffff),struct.pack('<BI',4,0),0xffffffff)],
      [protocol.TxnOut(100000000000000,_PAY2MINER),protocol.TxnOut(0,_PAY2MINER)],
      0xffffffff, b'' ) # genesis block only contains one transaction
