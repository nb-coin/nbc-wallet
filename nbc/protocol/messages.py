# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

import hashlib
import os
import struct
from binascii import hexlify

from .. import util
from . import format

__all__ = [ 'MsgFormatError', 'Message', 'UnknownMsgError',
  'Address', 'Block', 'GetAddress', 'GetBlocks', 'GetData',
  'GetHeaders', 'Headers', 'Inventory', 'MemoryPool', 'NotFound',
  'Ping', 'Pong', 'Reject', 'Transaction', 'Version', 'VersionAck',
  'UdpReject', 'UdpConfirm', 'UdpPeekState', 'MakeSheet', 'OrgSheet', 'SubmitSheet',
  'GetAccState', 'AccState', 'QueryHeaders', 'ReplyHeaders', 'GetUtxoState', 'UtxoState',
  'GetPoetTask', 'PoetReject', 'PoetInfo', 'PoetResult' ]

def _debug(obj, params):
  message = ['<%s' % obj.__class__.__name__]
  for (k, v) in params:
    if isinstance(v,(list,tuple)):
      message.append(('len(%s)=%d' % (k,len(v))))
      if len(v):
        k = '%s[0]' % k
        v = v[0]
    
    if v:
      if isinstance(v,format.NetworkAddress):
        text = '%s:%d' % (v.address, v.port)
      elif isinstance(v,format.InventoryVector):
        obj_type = 'unknown'
        if v.object_type <= 2:
          obj_type = ['error', 'tx', 'block'][v.object_type]
        text = '%s:%s' % (obj_type, hexlify(v.hash))
      elif isinstance(v,format.Txn):
        text = hexlify(v.hash)
      elif isinstance(v,format.BlockHeader):
        text = hexlify(v.hash)
      else:
        text = str(v)
      message.append(('%s=%s' % (k,text)))
    elif v == 0:
      message.append(('%s=%s' % (k,v)))
  
  return ' '.join(message) + '>'

class UnknownMsgError(Exception): pass  # when command not registed
class MsgFormatError(Exception): pass   # invalid message header

class Message(format.CompoundType):
  '''A message object. This base class is responsible for serializing and
     deserializing binary network payloads.

     Each message sub-class should specify an array of (name, FormatType)
     tuples named properties. See below for examples.

     Message subclasses will automatically be registered, unless they set
     not_regist = True.

     Messages are rigorously type checked for the properties that are given
     to ensure the bytes over the wire will be what was expected.'''
  
  command = None
  not_regist = False
  properties = []
  
  _magic = None  # only parsed messages will have a magic number
  magic = property(lambda s: s._magic)
  
  def binary(self, magic):
    payload = format.CompoundType.binary(self)
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    command = self.command.encode('latin-1')  # command must be '_a-zA-Z0-9'
    if len(command) > 12: raise Exception('command name too long')
    command = command + (b'\x00' * (12 - len(command)))  # pad to 12 bytes
    return magic + command + struct.pack('<I',len(payload)) + checksum + payload
  
  MessageTypes = dict()
  
  @staticmethod
  def register(msg_type):
    Message.MessageTypes[msg_type.command] = msg_type
  
  @staticmethod
  def first_msg_len(data):
    if len(data) < 20:  # not enough to determine payload size yet
      return None
    return struct.unpack('<I', data[16:20])[0] + 24
  
  @classmethod
  def parse(cls, data, magic):
    if data[0:4] != magic:  # check magic
      raise MsgFormatError('bad magic number')
    
    # get binary payload
    (length, ) = struct.unpack('<I', data[16:20])
    payload = data[24:24 + length]
    
    # check the checksum
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if data[20:24] != checksum:
      raise MsgFormatError('bad checksum')
    
    # get the correct class for this message's command
    command = data[4:16].strip(b'\x00').decode('latin-1')
    msg_type = cls.MessageTypes.get(command)
    if msg_type is None:
      raise UnknownMsgError('command: %r (%r)' % (command, data))
    
    # parse the properties using the correct class's parse
    (vl, message) = super(Message,msg_type).parse(payload)
    message._magic = magic
    return message
  
  @property
  def name(self):  # should overridden in sub-class, it determines which command_* will be called
    return self.command
  
  def _debug(self):
    return _debug(self,[])

#-----------
class ExpansionLnk(Message):  # not in using yet
  command = 'expansion'
  
  properties = [
    ('version', format.FtNumber('I')),
    ('link_mask', format.FtNumber('H')), # link number is: link_mask + 1
    ('encode_msg', format.FtBytes(16)),  # version2, link_mask2, mining_mask4, coin_name8
    ('timestamp', format.FtNumber('I',allow_float=True)),
    ('sig_mng', format.FtVarString()),
  ]
  
  def _debug(self):
    return _debug(self,[
      ('v', self.version), ('m', self.link_mask),
    ])

#-----------
class Version(Message):
  command = 'version'
  
  properties = [
    ('version', format.FtNumber('I')),
    ('link_no', format.FtNumber('I')),
    ('services', format.FtNumber('Q')),
    ('timestamp', format.FtNumber('q',allow_float=True)),
    ('addr_recv', format.FtNetworkAddressNoTimestamp()),
    ('addr_from', format.FtNetworkAddressNoTimestamp()),
    ('nonce', format.FtBytes(8)),
    ('user_agent', format.FtVarString()),
    ('start_height', format.FtNumber('i')),
    ('relay', format.FtOptional(format.FtNumber('B'), True)),  # no use yet
  ]
  
  def _debug(self):
    return _debug(self,[
      ('v', self.version), ('s', self.services),
      ('ua', self.user_agent), ('sh', self.start_height),
    ])

class VersionAck(Message):
  command = 'verack'
  name = 'version_ack'
  
  properties = [
    ('link_no', format.FtNumber('I')),
  ]
  
  def _debug(self):
    return _debug(self,[ ('link_no',self.link_no) ])

class Address(Message):
  command = 'addr'
  name = 'address'
  
  properties = [
    ('link_no', format.FtNumber('I')),
    ('addr_list',format.FtArray(format.FtNetworkAddress(),max_length=1000)),
  ]
  
  def _debug(self):
    return _debug(self, [('a', self.addr_list)])

class Inventory(Message):
  command = 'inv'
  name = 'inventory'
  
  properties = [
    ('link_no', format.FtNumber('I')),
    ('inventory', format.FtArray(format.FtInventoryVector(), max_length = 50000)),
  ]
  
  def _debug(self):
    return _debug(self, [('i', self.inventory)])

class GetData(Inventory):
  command = 'getdata'
  name = 'get_data'

class NotFound(Inventory):
  command = 'notfound'
  name = 'not_found'

class GetBlocks(Message):
  command = 'getblocks'
  name = 'get_blocks'
  
  properties = [
    ('version', format.FtNumber('I')),
    ('link_no', format.FtNumber('I')),
    ('block_locator_hashes', format.FtArray(format.FtBytes(32), 1)),
    ('hash_stop', format.FtBytes(32)),
  ]
  
  def _debug(self):
    return _debug(self, [('blh', [hexlify(h) for h in self.block_locator_hashes])])

class GetHeaders(GetBlocks):
  command = 'getheaders'
  name = 'get_headers'

class Transaction(Message):
  command = 'tx'
  name = 'transaction'
  
  properties = [
    ('version', format.FtNumber('I')),
    ('tx_in', format.FtArray(format.FtTxnIn(), 1)),
    ('tx_out', format.FtArray(format.FtTxnOut(), 1)),
    ('lock_time', format.FtNumber('I')),
    ('sig_raw', format.FtVarString()),
  ]
  
  def _debug(self):
    return _debug(self, [('in', self.tx_in), ('out', self.tx_out)])
  
  @staticmethod
  def from_txn(txn):
    return Transaction(txn.version,txn.tx_in,txn.tx_out,txn.lock_time,txn.sig_raw)

class Block(Message):
  command = 'block'
  
  properties = [
    ('version', format.FtNumber('I')),
    ('link_no', format.FtNumber('I')),
    ('prev_block', format.FtBytes(32)),
    ('merkle_root', format.FtBytes(32)),
    ('timestamp', format.FtNumber('I', allow_float = True)),
    ('bits', format.FtNumber('I')),
    ('nonce', format.FtNumber('I')),
    ('miner', format.FtBytes(32)),
    ('sig_tee', format.FtVarString()),
    ('txns', format.FtArray(format.FtTxn())),
  ]

  @staticmethod
  def from_block(block):
    txns = [txn.txn for txn in block.txns]
    if block.txn_count != len(txns):
      raise Exception('invalid transaction number: %i != %i',(block.txn_count,len(txns)))
    return Block( block.version, block.link_no, block.previous_hash,
                  block.merkle_root, block.timestamp, block.bits, block.nonce,
                  block.miner, block.sig_tee, txns )
  
  def _debug(self):
    block_head = util.get_block_header(self.version, self.link_no, self.prev_block,
      self.merkle_root, self.timestamp, self.bits, self.nonce)
    return _debug(self, [('h', hexlify(block_head)), ('t', self.txns)])
  
  def make_header(self):
    return format.BlockHeader( self.version, self.link_no, self.prev_block,
      self.merkle_root, self.timestamp, self.bits, self.nonce, self.miner,
      self.sig_tee, len(self.txns) )

class Headers(Message):
  command = 'headers'
  
  properties = [
    ('headers', format.FtArray(format.FtBlockHeader())),
  ]

  def _debug(self):
    return _debug(self, [('h', self.headers)])

class GetAddress(VersionAck):
  command = 'getaddr'
  name = 'get_address'
  
  properties = [
    ('link_no', format.FtNumber('I')),
  ]
  
  def _debug(self):
    return _debug(self, [('link_no', self.link_no)])

class MemoryPool(VersionAck):
  command = 'mempool'
  name = 'memory_pool'

class Ping(Message):
  command = 'ping'
  
  properties = [
    ('nonce', format.FtBytes(8)),
  ]
  
  def _debug(self):
    return _debug(self, [('n', hexlify(self.nonce))])

class Pong(Ping):
  command = 'pong'
  
  properties = [
    ('nonce', format.FtBytes(8)),
    ('link_no', format.FtNumber('I')),
  ]

class Reject(Message):
  command = 'reject'
  
  properties = [
    ('message', format.FtVarString()),
    ('ccode', format.FtNumber('B')),
    ('reason', format.FtVarString()),
  ]
  
  def _debug(self):
    return _debug(self, [('m', self.message), ('r', self.reason)])

# API Service
#------------

class UdpReject(Message):
  command = 'reject'
  name = 'reject'
  
  properties = [
    ('sequence', format.FtNumber('I')),
    ('message', format.FtVarString()),
    ('source', format.FtVarString()),
  ]

class UdpConfirm(Message):
  command = 'confirm'
  name = 'confirm'
  
  properties = [
    ('hash', format.FtBytes(32)),
    ('arg', format.FtNumber('q')),
  ]

class UdpPeekState(Message):
  command = 'peekstate'
  name = 'peek_state'
  
  properties = [
    ('hash', format.FtBytes(32)),
  ]

class MakeSheet(Message):
  command = 'makesheet'
  name = 'make_sheet'
  
  properties = [
    ('vcn', format.FtNumber('H')),
    ('sequence', format.FtNumber('I')),
    ('pay_from', format.FtArray(format.FtPayFrom, 1)),
    ('pay_to', format.FtArray(format.FtPayTo, 1)),
    ('scan_count', format.FtNumber('H')), # should at least scan N utxos, 0 for default (512 or 10)
    ('min_utxo', format.FtNumber('q')),   # query any fee > min_utxo
    ('max_utxo', format.FtNumber('q')),   # 0 for no limit, else, fee <= max_utxo
    ('sort_flag', format.FtNumber('I')),  # 0 for no sort, else sorted
    ('last_uocks', format.FtArray(format.FtNumber('q'), 1)) # same length as pay_from
  ]

class OrgSheet(Message):
  command = 'orgsheet'
  name = 'org_sheet'
  
  properties = [
    ('sequence', format.FtNumber('I')),
    ('pks_out', format.FtArray(format.FtVarStrList, 1)),
    ('last_uocks', format.FtArray(format.FtNumber('q'), 1)),  # 0 means has scan all, else, next utxo should > last_uock
    
    ('version', format.FtNumber('I')),
    ('tx_in', format.FtArray(format.FtTxnIn, 1)),
    ('tx_out', format.FtArray(format.FtTxnOut, 1)),
    ('lock_time', format.FtNumber('I')),
    
    ('signature', format.FtVarString()),
  ]
  
  def _debug(self):
    return _debug(self,[('in',len(self.tx_in)),('out',len(self.tx_out)),('sn',self.sequence)])

class SubmitSheet(Transaction):
  command = 'submitsheet'
  name = 'submit_sheet'

class GetAccState(Message):
  command = 'getaccstate'
  name = 'get_account_state'
  
  properties = [
    ('account', format.FtVarString()),
    ('uock', format.FtNumber('q')),
    ('uock2', format.FtNumber('q')),
  ]
  
  def _debug(self):
    return _debug(self,[('a',self.account)])

class AccState(Message):
  command = 'accstate'
  name = 'account_state'
  
  properties = [
    ('link_no', format.FtNumber('I')),
    ('timestamp', format.FtNumber('I',allow_float=True)),
    ('account', format.FtVarString()),
    ('search', format.FtNumber('I')),
    ('found', format.FtArray(format.FtUockValue)),
  ]
  
  def _debug(self):
    return _debug(self,[('s',self.search),('n',len(self.found))])

class QueryHeaders(Message):
  command = 'queryheaders'
  name = 'query_headers'
  
  properties = [
    ('hash', format.FtBytes(32)),      # ignore when hash is b'\x00' * 32
    ('hi', format.FtArray(format.FtNumber('I'))),
  ]

class ReplyHeaders(Message):
  command = 'replyheaders'
  name = 'reply_headers'
  
  properties = [
    ('link_no', format.FtNumber('I')),
    ('heights', format.FtArray(format.FtNumber('I'))),
    ('txcks', format.FtArray(format.FtNumber('q'))),
    ('headers', format.FtArray(format.FtBlockHeader)),
  ]
  
  def _debug(self):
    return _debug(self,[('h',self.heights)])

class GetUtxoState(Message):
  command = 'getutxostate'
  name = 'get_utxo_state'
  
  properties = [
    ('account', format.FtVarString()),
    ('num', format.FtNumber('I')),
    ('uock', format.FtArray(format.FtUockValue)),
  ]
  
  def _debug(self):
    return _debug(self,[('n',self.num),('u',self.uock)])

class UtxoState(Message):
  command = 'utxostate'
  name = 'utxo_state'
  
  properties = [
    ('link_no', format.FtNumber('I')),
    ('heights', format.FtArray(format.FtNumber('I'))),
    ('indexes', format.FtArray(format.FtNumber('I'))),  # (txn_index << 16) | out_index
    ('txns', format.FtArray(format.FtTxn)),
  ]
  
  def _debug(self):
    return _debug(self,[('hi',self.heights)])

class GetPoetTask(Message):
  command = 'poettask'
  name = 'poet_task'
  
  properties = [
    ('link_no', format.FtNumber('I')),
    ('curr_id', format.FtNumber('I')),
    ('timestamp', format.FtNumber('I',allow_float=True)),
  ]
  
  def _debug(self):
    return _debug(self,[('id',self.curr_id)])

class PoetReject(Message):
  command = 'poetreject'
  name = 'poet_reject'
  
  properties = [
    ('sequence', format.FtNumber('I')),
    ('timestamp', format.FtNumber('I',allow_float=True)),
    ('reason', format.FtVarString()),
  ]
  
  def _debug(self):
    return _debug(self,[('id',self.sequence),('tm',self.timestamp),('desc',self.reason)])

class PoetInfo(Message):
  command = 'poetinfo'
  name = 'poet_info'
  
  properties = [
    ('link_no', format.FtNumber('I')),
    ('curr_id', format.FtNumber('I')),
    ('block_hash', format.FtBytes(32)),
    ('bits', format.FtNumber('I')),
    ('height', format.FtNumber('I')),
    ('prev_time', format.FtNumber('q',allow_float=True)),
    ('curr_time', format.FtNumber('q',allow_float=True)),
    ('txn_num', format.FtNumber('I')),
  ]
  
  def _debug(self):
    return _debug(self,[('id',self.curr_id),('hi',self.height),('n',self.txn_num)])

class PoetResult(Message):
  command = 'poetresult'
  name = 'poet_result'
  
  properties = [
    ('link_no', format.FtNumber('I')),
    ('curr_id', format.FtNumber('I')),
    ('miner', format.FtBytes(32)),
    ('sig_tee', format.FtVarString()),
  ]
  
  def _debug(self):
    return _debug(self,[('id',self.curr_id),('m',hexlify(self.miner))])
