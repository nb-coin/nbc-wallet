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
  
  name    = "newbitcoin"
  symbols = ['NBC']         # all symbols
  symbol  = symbols[0]      # primary symbol
  
  mining_coin_type   = b'\x00'
  currency_coin_type = b'\x00'
  protocol_version   = 0
  
  magic = b'\xf9\x6e\x62\x63'
  
  raw_seed = ('raw%.pinp.io',20303)    # tcp listen port is 20303
  
  genesis_version = 1
  genesis_block_hash = decodeHex(b'9488469356089fea9638efa2bb61ab0740b2037178292bdd665933b0d3020000')
  genesis_merkle_root = decodeHex(b'21a21e382d54c4d455c86df05162c39e244545589023889630ecc09ba2e93bca')
  genesis_timestamp = 1544614742
  genesis_bits = 5000
  genesis_miner = decodeHex(b'd20d21e17681d6a984508f4138592dfa6b592e11e982aaad2af7627440a691d6')
  genesis_nonce = 244224399
  genesis_signature = decodeHex(b'3045022014008aeceb52bd81b6ccd863029c5a8971a913cdcecffb5e358b8336d789795202210088a3f0a2698c25442801cda2ea5af9e8a3dcfde39dd62a40b2f21039def59fed00')
  genesis_txn = protocol.Txn( 1,
      [protocol.TxnIn(protocol.OutPoint(b'\x00'*32,0xffffffff),struct.pack('<BI',4,0),0xffffffff)],
      [protocol.TxnOut(420000000000000,_PAY2MINER),protocol.TxnOut(0,_PAY2MINER)],
      0xffffffff, b'' ) # genesis block only contains one transaction
